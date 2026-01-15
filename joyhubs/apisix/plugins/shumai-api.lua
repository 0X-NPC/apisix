--
-- 数脉API-请求签名支持插件（表单提交方式）
-- v1.0 (20260115)
--
local core = require("apisix.core")
local md5 = require("resty.md5")
local str_util = require("resty.string")
local ngx = ngx
local ngx_time = ngx.now

local plugin_name = "shumai-api"

-- 定义插件配置的Schema
local schema = {
    type = "object",
    properties = {
        app_id = {type = "string", minLength = 1},
        app_secret = {type = "string", minLength = 1},
        sign_param_name = {type = "string", default = "sign", minLength = 1}
    },
    required = {"app_id", "app_secret"}
}

-- priority数值越大越早执行,在URL重写和限流检查之后执行，节省CPU资源
local _M = {
    version = 0.1,
    priority = 1000,
    name = plugin_name,
    schema = schema,
}

function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

-- 生成MD5签名
-- 规则：MD5(appId & timestamp & AppSecret)
local function generate_signature(app_id, timestamp, app_secret)
    local m = md5:new()
    if not m then
        core.log.error("failed to create md5 object")
        return nil
    end

    -- 拼接字符串
    local source_str = app_id .. "&" .. tostring(timestamp) .. "&" .. app_secret

    local ok = m:update(source_str)
    if not ok then
        core.log.error("failed to add data to md5")
        return nil
    end

    local digest = m:final()
    if not digest then
        core.log.error("failed to get md5 digest")
        return nil
    end

    return str_util.to_hex(digest)
end

function _M.rewrite(conf, ctx)
    -- 1. 检查 Content-Type 是否为 application/x-www-form-urlencoded
    local content_type = core.request.header(ctx, "Content-Type")
    if not content_type or not core.string.find(content_type, "application/x-www-form-urlencoded", 1, true) then
        core.log.info("[shumai-api] plugin skipped: content-type not supported: ", content_type)
        return
    end

    -- 2. 读取请求体
    local body_data, err = core.request.get_body(nil, ctx)

    if err then
        core.log.error("failed to get request body: ", err)
        return 500, {message = "failed to read request body: " .. err}
    end

    -- 如果 body 为 nil (比如空包体)，初始化为空字符串以避免拼接报错
    if not body_data then
        body_data = ""
    end

    -- 3. 获取当前毫秒级时间戳
    -- ngx.now() 返回的是秒（带小数），乘以1000取整
    local timestamp = math.floor(ngx_time() * 1000)

    -- 4. 计算签名
    local signature = generate_signature(conf.app_id, timestamp, conf.app_secret)
    if not signature then
        return 500, {message = "failed to generate signature"}
    end

    -- 5. 拼接新参数
    -- 格式：old_body & sign_param_name = signature
    -- 注意处理空 body 的情况
    local new_body
    local params_part = "appid=" .. conf.app_id .. "&timestamp=" .. timestamp .. "&" .. conf.sign_param_name .. "=" .. signature
    local sign_part = conf.sign_param_name .. "=" .. signature

    if body_data == "" then
        new_body = params_part
    else
        new_body = body_data .. "&" .. params_part
    end

    -- 6. 回写 Body
    ngx.req.set_body_data(new_body)
end

return _M
