--
-- 请求响应结果JSON包装插件（response-json-wrap）
--
local core = require("apisix.core")
local ngx = ngx
local cjson = require("cjson.safe")

local plugin_name = "response-json-wrap"

local schema = {
    type = "object",
    properties = {
        formats = {
            type = "array",
            items = {
                type = "string",
                enum = { "json", "xml", "text", "html" }
            },
            default = { "json" }
        },
        messages = {
            type = "object",
            additionalProperties = {
                type = "string"
            },
            default = {
                ["400"] = "Bad Request",
                ["401"] = "Unauthorized",
                ["403"] = "Forbidden",
                ["404"] = "Not Found",
                ["500"] = "Internal Server Error"
            }
        }
    }
}

-- 各 format 对应的 MIME 类型前缀表
local FORMAT_MIME_MAP = {
    json = { "application/json" },
    xml = { "application/xml", "text/xml" },
    text = { "text/plain" },
    html = { "text/html" }
}

local function match_content_type(content_type, formats)
    if not content_type then
        return false
    end

    content_type = string.lower(content_type):gsub("%s+", "")

    for _, fmt in ipairs(formats or {}) do
        local mime_list = FORMAT_MIME_MAP[fmt]
        if mime_list then
            for _, mime in ipairs(mime_list) do
                if string.sub(content_type, 1, #mime) == mime then
                    return true, fmt
                end
            end
        end
    end

    return false
end

local function try_decode_json(body)
    if not body or #body == 0 then
        return nil, false
    end
    local decoded = cjson.decode(body)
    if decoded ~= nil then
        return decoded, true
    end
    return body, false
end

local function wrap_response(conf, status, body, is_json)
    local success = status >= 200 and status < 300
    local msg = conf.messages[tostring(status)] or (tostring(status) .. " ERROR")

    return {
        code = status,
        success = success,
        message = success and "" or msg,
        content = body
    }
end

local _M = {
    version = 0.1,
    priority = 1000, --确保在gzip插件（995）之前执行，数字越大越早执行
    name = plugin_name,
    schema = schema,
}

function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

-- 强制要求上游返回明文，避免GZIP结果返回，以便插件处理
function _M.rewrite(conf, ctx)
    core.request.set_header(ctx, "Accept-Encoding", "")
end

-- 判断是否需要包裹
function _M.header_filter(conf, ctx)
    local content_type = ngx.header["content-type"]
    local matched, fmt = match_content_type(content_type, conf.formats)
    if matched then
        ctx.wrap_enabled = true
        ctx.wrap_format = fmt
        -- 清除content-length，因为包装后的长度会变
        ngx.header["content-length"] = nil
        -- 设置响应头
        ngx.header["content-type"] = "application/json; charset=utf-8"
    else
        ctx.wrap_enabled = false
    end
end

-- 执行响应体重写
function _M.body_filter(conf, ctx)
    if not ctx.wrap_enabled then
        return
    end

    local body = core.response.hold_body_chunk(ctx)
    -- 数据还没传完，继续等待
    if ngx.arg[2] == false and not body then
        return
    end

    local status = ngx.status
    local is_json = ctx.wrap_format == "json"
    local content = body

    if is_json then
        local decoded, ok = try_decode_json(body)
        content = decoded
        is_json = ok
    end

    local wrapped = wrap_response(conf, status, content, is_json)
    local ok, new_body = pcall(cjson.encode, wrapped)
    if not ok then
        core.log.err(plugin_name, ": Failed to encode final response (upstream response may contain invalid UTF-8 bytes): ", new_body)

        -- 502 Bad Gateway
        local safe_status = 502
        ngx.status = safe_status

        local safe_wrapped = {
            code = safe_status,
            success = false,
            message = "Bad Gateway: Upstream response contained invalid characters",
            content = nil -- 保证 content 为 nil
        }
        new_body = cjson.encode(safe_wrapped)
    end

    ngx.header["content-length"] = nil
    ngx.arg[1] = new_body
    ngx.arg[2] = true -- 标记这是最后一块数据
end

return _M
