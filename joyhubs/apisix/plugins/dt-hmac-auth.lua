-- *** 数栖平台-数据服务认证插件 (dt-hmac-auth) ***
-- 请求头说明：
--    X-AURORA-APPKEY       : AK (APPKEY_HEADER)
--    X-AURORA-SIGN         : 签名字符串 (SIGN_HEADER)
--    X-AURORA-TIMESTAMP    : 时间戳 (TIMESTAMP_HEADER)
--    CONTENT-MD5           : RequestBody MD5
-- *** ------------------------------------ ***
local ngx = ngx
local abs = math.abs
local ngx_time = ngx.time
local ipairs = ipairs
local core = require("apisix.core")
local hmac = require("resty.hmac")
local consumer = require("apisix.consumer")
local ngx_decode_base64 = ngx.decode_base64
local ngx_encode_base64 = ngx.encode_base64
local plugin_name = "dt-hmac-auth"
-- 引入 resty.md5 和 resty.string 用于 Hex 编码
local resty_md5 = require("resty.md5")
local resty_string = require("resty.string")
local ngx_re = require("ngx.re")
local schema_def = require("apisix.schema_def")
local auth_utils = require("apisix.utils.auth")

-- HTTP Header 常量
local APPKEY_HEADER = "X-AURORA-APPKEY"
local SIGN_HEADER = "X-AURORA-SIGN"
local TIMESTAMP_HEADER = "X-AURORA-TIMESTAMP"
local CONTENT_MD5_HEADER = "CONTENT-MD5"

local schema = {
    type = "object",
    title = "work with route or service object",
    properties = {
        clock_skew = {
            type = "integer",
            default = 300,
            minimum = 1
        },
        validate_request_body = {
            type = "boolean",
            title = "A boolean value telling the plugin to enable body validation",
            default = false,
        },
        hide_credentials = { type = "boolean", default = false },
        anonymous_consumer = schema_def.anonymous_consumer_schema,
    },
}

local consumer_schema = {
    type = "object",
    title = "work with consumer object",
    properties = {
        key_id = { type = "string", minLength = 1, maxLength = 256 },
        secret_key = { type = "string", minLength = 1, maxLength = 256 },
    },
    encrypt_fields = { "secret_key" },
    required = { "key_id", "secret_key" },
}

local _M = {
    version = 0.2,
    priority = 2530,
    type = 'auth',
    name = plugin_name,
    schema = schema,
    consumer_schema = consumer_schema
}

function _M.check_schema(conf, schema_type)
    core.log.info("input conf: ", core.json.delay_encode(conf))

    if schema_type == core.schema.TYPE_CONSUMER then
        return core.schema.check(consumer_schema, conf)
    else
        return core.schema.check(schema, conf)
    end
end

local function get_consumer(key_id)
    if not key_id then
        return nil, "missing " .. APPKEY_HEADER
    end

    local cur_consumer, _, err = consumer.find_consumer(plugin_name, "key_id", key_id)
    if not cur_consumer then
        return nil, err or "Invalid " .. APPKEY_HEADER .. " (Consumer not found)"
    end
    core.log.info("consumer: ", core.json.delay_encode(consumer, true))

    return cur_consumer
end


---
-- queryString参数排序
--
local function build_query_string()
    local raw_query = ngx.var.query_string
    if not raw_query or raw_query == "" then
        return ""
    end

    local unique_pairs = {}
    local keys = {}

    for key_value in string.gmatch(raw_query, "([^&]+)") do
        local eq_pos = string.find(key_value, "=", 1, true)
        local key, value
        if eq_pos then
            key = string.sub(key_value, 1, eq_pos - 1)
            value = string.sub(key_value, eq_pos + 1)
        else
            key = key_value
            value = nil
        end

        if unique_pairs[key] == nil then
            unique_pairs[key] = value
            table.insert(keys, key)
        end
    end

    if #keys == 0 then
        return ""
    end

    table.sort(keys)

    local parts = {}
    for i, key in ipairs(keys) do
        local value = unique_pairs[key]
        if value ~= nil then
            table.insert(parts, key .. "=" .. value)
        else
            table.insert(parts, key)
        end
    end

    return table.concat(parts, "&")
end


---
-- 生成请求体MD5字符串（标准Content-MD5实现）
--
local function calculate_content_md5(body)
    local m = resty_md5:new()
    m:update(body or "")
    local digest_raw = m:final()
    return ngx_encode_base64(digest_raw)
end

---
-- 生成签名字符串
--
local function generate_signature(secret_key, params)
    local request_method = core.request.get_method()
    -- 1.构造参与签名的queryString字符串（参数字典排序）
    local queryString = build_query_string()

    -- 2.构造待签名字符串
    local stringToSign
    if request_method == "POST" or request_method == "PUT" then
        if not params.content_md5 then
            -- POST/PUT 必须有 CONTENT-MD5
            return nil, "Missing " .. CONTENT_MD5_HEADER .. " for " .. request_method
        end
        stringToSign = request_method .. "\n" .. queryString .. "\n" .. params.timestamp .. "\n" .. params.content_md5
    else
        stringToSign = request_method .. "\n" .. queryString .. "\n" .. params.timestamp
    end

    core.log.info("string to sign: ", stringToSign)

    -- 3. 计算签名
    local hmac_sha256 = hmac:new(secret_key, hmac.ALGOS.SHA256)
    hmac_sha256:update(stringToSign)
    local hmac_raw = hmac_sha256:final()
    local hmac_hex = resty_string.to_hex(hmac_raw)
    local signature = ngx_encode_base64(hmac_hex)

    return signature, nil
end


---
-- 请求认证校验
--
local function validate(ctx, conf, params)
    if not params then
        return nil
    end

    -- 1.检查所有必需的 Header
    if not params.appkey or not params.signature or not params.timestamp then
        return nil, "Missing required headers (" .. APPKEY_HEADER .. ", " .. SIGN_HEADER .. ", " .. TIMESTAMP_HEADER .. ")"
    end

    -- 2.查找 Consumer (获取 AppSecret)
    local consumer, err = get_consumer(params.appkey)
    if err then
        return nil, err
    end

    local consumer_conf = consumer.auth_conf
    local secret_key = consumer_conf and consumer_conf.secret_key
    if not secret_key then
        return nil, "No secret_key found for consumer " .. params.appkey
    end

    -- 3.验证时间戳
    if conf.clock_skew and conf.clock_skew > 0 then
        -- 客户端（Java）提供是毫秒单位，如：System.currentTimeMillis()
        local timestamp_num = tonumber(params.timestamp)
        if not timestamp_num then
            return nil, "Invalid " .. TIMESTAMP_HEADER .. " (not a number)"
        end

        -- ngx.time() 是秒 (float), 乘以 1000 得到毫秒
        local server_time_ms = ngx.time() * 1000
        local diff_ms = abs(server_time_ms - timestamp_num)

        -- conf.clock_skew 是秒, 乘以 1000 得到毫秒
        if diff_ms > (conf.clock_skew * 1000) then
            return nil, "Clock skew exceeded. Server time(ms): " .. server_time_ms .. ", Request time(ms): " .. timestamp_num
        end
    end

    -- 4.验证Body（Content-MD5）
    if conf.validate_request_body then
        local req_body, err = core.request.get_body()
        if err then
            return nil, err
        end

        req_body = req_body or ""
        local digest_created = calculate_content_md5(req_body)

        if digest_created ~= params.content_md5 then
            return nil, "Invalid " .. CONTENT_MD5_HEADER .. " (Body digest mismatch)"
        end
    end

    -- 5.生成并验证签名
    local generated_signature, gen_err = generate_signature(secret_key, params)
    if gen_err then
        return nil, gen_err
    end

    if params.signature ~= generated_signature then
        core.log.warn("Invalid signature. Client: ", params.signature, " Server: ", generated_signature)
        return nil, "Invalid signature"
    end

    -- 验证通过
    return consumer
end


---
-- 检查和提取认证所需的参数
--
local function retrieve_dtwave_fields(ctx)
    local params = {}

    params.appkey = core.request.header(ctx, APPKEY_HEADER)
    params.signature = core.request.header(ctx, SIGN_HEADER)
    params.timestamp = core.request.header(ctx, TIMESTAMP_HEADER)
    params.content_md5 = core.request.header(ctx, CONTENT_MD5_HEADER)

    if not params.appkey then
        return nil, "missing " .. APPKEY_HEADER .. " header"
    end

    return params
end

local function find_consumer(conf, ctx)
    local params, err = retrieve_dtwave_fields(ctx)
    if err then
        if not auth_utils.is_running_under_multi_auth(ctx) then
            core.log.warn("client request can't be validated: ", err)
        end
        return nil, nil, "client request can't be validated: " .. err
    end

    local validated_consumer, err = validate(ctx, conf, params)
    if not validated_consumer then
        err = "client request can't be validated: " .. (err or "Invalid signature")
        if auth_utils.is_running_under_multi_auth(ctx) then
            return nil, nil, err
        end
        core.log.warn(err)
        return nil, nil, "client request can't be validated"
    end

    local consumers_conf = consumer.consumers_conf(plugin_name)
    return validated_consumer, consumers_conf, err
end

function _M.rewrite(conf, ctx)
    local cur_consumer, consumers_conf, err = find_consumer(conf, ctx)
    if not cur_consumer then
        if not conf.anonymous_consumer then
            return 401, { message = err }
        end
        cur_consumer, consumers_conf, err = consumer.get_anonymous_consumer(conf.anonymous_consumer)
        if not cur_consumer then
            if auth_utils.is_running_under_multi_auth(ctx) then
                return 401, err
            end
            core.log.error(err)
            return 401, { message = "Invalid user authorization" }
        end
    end

    if conf.hide_credentials then
        core.request.set_header(APPKEY_HEADER, nil)
        core.request.set_header(SIGN_HEADER, nil)
        core.request.set_header(TIMESTAMP_HEADER, nil)
        core.request.set_header(CONTENT_MD5_HEADER, nil)
    end

    consumer.attach_consumer(ctx, cur_consumer, consumers_conf)
end

return _M
