--
-- 赣湘边API-支持插件
-- 特性说明：
-- 1. 请求方式：POST-JSON请求体提交方式(Method: POST, Content-Type: application/json)
-- 2. 加密算法：RSA（加密后编码方式为Base64）
-- 3. 参数校验：支持对请求体属性进行非空校验
-- v0.1 (2026/03/03)
--
local core     = require("apisix.core")
local pkey     = require("resty.openssl.pkey")
local ngx      = ngx
local type     = type
local ipairs   = ipairs
local tostring = tostring

-- Localize the OpenResty method for performance and availability
local req_set_body_data = ngx.req.set_body_data
local ngx_encode_base64 = ngx.encode_base64
local ngx_decode_base64 = ngx.decode_base64

local plugin_name = "gxb-api"

local schema = {
    type = "object",
    properties = {
        public_key = {
            type = "string",
            minLength = 1,
            description = "DER格式公钥字符串（Base64编码，无PEM头尾）"
        },
        encrypt_fields = {
            type = "array",
            items = { type = "string" },
            default = { "idNoMan", "nameMan", "idNoWoman", "nameWoman", "idNo", "name" }
        },
        encode_base64 = { type = "boolean", default = true },
        validation = {
            type = "array",
            items = { type = "string" },
            description = "需要校验非空的属性名称列表"
        }
    },
    required = { "public_key" }
}

-- 插件元信息
local _M = {
    version  = 0.1,
    priority = 2501,
    name     = plugin_name,
    schema   = schema,
}

-- 创建 LRU 缓存，用于存储 RSA 实例
-- 避免每个请求都去解析公钥（极耗费 CPU）
local rsa_obj_cache = core.lrucache.new({
    ttl = 300,    -- 缓存5分钟
    count = 100   -- 最多缓存100个公钥实例
})

-- 创建RSA实例
local function create_rsa_obj(public_key_b64)
    -- 容错支持：移除多余的空白字符（包括空格、换行符 \n、回车符 \r）
    local clean_b64 = string.gsub(public_key_b64, "%s+", "")

    -- 解码为DER格式(对应Java X509)公钥
    local der_bytes = ngx_decode_base64(clean_b64)
    if not der_bytes then
        return nil, "failed to decode base64 public key configuration"
    end

    -- 使用内置的 resty.openssl.pkey 解析公钥
    local pub, err = pkey.new(der_bytes, {
        format = "DER",
        type = "pu"
    })

    if not pub then
        return nil, "failed to initialize RSA: " .. (err or "unknown")
    end
    return pub
end

-- RSA分段加密
local function rsa_chunked_encrypt(rsa_obj, plaintext)
    local max_encrypt = 244
    local input_len = #plaintext

    if input_len == 0 then
        return ""
    end

    -- 如果明文长度未超过最大限制，直接一次性加密，跳过循环和内存切片开销
    if input_len <= max_encrypt then
        return rsa_obj:encrypt(plaintext)
    end

    local encrypted_chunks = {}
    local offset = 1

    -- 循环对数据分段加密
    while offset <= input_len do
        -- string.sub 截取字节流，超出 input_len 范围会自动截断
        local chunk = string.sub(plaintext, offset, offset + max_encrypt - 1)

        local encrypted_chunk, err = rsa_obj:encrypt(chunk)
        if not encrypted_chunk then
            return nil, err
        end

        table.insert(encrypted_chunks, encrypted_chunk)
        offset = offset + max_encrypt
    end

    -- 将所有加密后的二进制数据块拼接
    return table.concat(encrypted_chunks)
end

function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

-- 在 rewrite 阶段处理请求体修改
function _M.rewrite(conf, ctx)
    -- 0.幂等性处理，避免重复执行
    if ctx._gxb_executed then return end

    -- 1. 仅对可能带有请求体的方法进行拦截处理
    if core.request.get_method() ~= "POST" then return 405 end
    local ct = core.request.header(ctx, "Content-Type")
    if not ct or not string.find(ct, "application/json", 1, true) then return 400 end

    -- 2. 读取请求体
    local req_body, err = core.request.get_body()
    if not req_body then return 400 end

    -- 3. 解析 JSON
    local success, body_json = pcall(core.json.decode, req_body)
    if not success or type(body_json) ~= "table" then return 400 end

    -- 4. 校验参数非空
    if conf.validation and #conf.validation > 0 then
        for _, field in ipairs(conf.validation) do
            local val = body_json[field]
            -- 如果属性值为 nil 或者空字符串，直接返回 400 错误
            if val == nil or val == "" then
                core.log.warn("gxb-api: validation failed, missing or empty field: ", field)
                return 400, { code = 400, message = "Invalid request: missing or empty required field '" .. field .. "'" }
            end
        end
    end

    -- 5. 执行 RSA 加密及 Base64 处理
    local public_key = conf.public_key
    -- 使用 LRU 缓存获取公钥对象，提升性能
    local rsa_obj, rsa_err = rsa_obj_cache(public_key, nil, create_rsa_obj, public_key)
    if not rsa_obj then
        core.log.error("gxb-api: failed to load rsa object, err: ", rsa_err)
        return 500, { code = 500, message = "Failed to load RSA object: " .. tostring(rsa_err) }
    end

    local fields = conf.encrypt_fields
    for _, field in ipairs(fields) do
        local val = body_json[field]
        -- 仅对存在的、类型为字符串的值进行加密
        if val and type(val) == "string" then
            local encrypted, enc_err = rsa_chunked_encrypt(rsa_obj, val)
            if not encrypted then
                core.log.error("gxb-api: failed to encrypt field [", field, "], err: ", enc_err)
                return 500, { code = 500, message = "Failed to encrypt field: " .. field }
            end
            if conf.encode_base64 then
                encrypted = ngx_encode_base64(encrypted)
            end
            -- 新值替换到请求体JSON对象属性上
            body_json[field] = encrypted
        end
    end

    -- 6. 数据发生变更，则重写请求体
    local new_body_json_string = core.json.encode(body_json)
    req_set_body_data(new_body_json_string)

    core.log.info("new body json:", new_body_json_string)

    -- 设置标志位，表示已成功执行，避免多次执行
    ctx._gxb_executed = true
end

return _M
