--
-- ** 文件日志增强插件 **
-- 功能说明：
-- V0.4 - 2026/03/03
-- 1. 新增 enable_code_match 配置项（默认true）。若配置为false，则不再解析响应体，直接将标记值设为not_match_tag的值，并在日志中增加 match_enabled 字段以标识状态。
--
-- V0.3 - 2026/02/03
-- 1. 增强 code_values 配置，支持字符串类型匹配，兼容原有数字匹配
-- 2. 增加 code_value 字段记录功能，将实际提取到的比对属性值记录到日志中，便于对账
--
-- V0.2 - 2025/11/14
-- 1. 增加响应体多层嵌套场景子对象属性值匹配支持（注意：不支持非完整JSON数据格式降级为正则匹配模式）
--
-- V0.1
-- 1. 解析请求原始响应结果（只支持JSON格式响应），判断结果中是否包含指定的属性值，如果包含则添加新的指定属性到访问日志中。
-- 2. 属性匹配有增强实现处理
--  2.1 APISIX对响应体提取有限制，默认最大为512KiB（MAX_REQ_BODY=524288），属性值匹配时会考虑截断情况并去除无效的UTF8字节，保证获取到可以正常编码的字符串
--  2.2 获取到截断后的响应体字符串之后，属性值匹配降级为正则匹配模式；
-- 3. 支持配置用于匹配的属性名（code_name参数）以及属性值列表（code_values），只要包含属性值列表中任意一个值则符合要求;
-- 4. 支持配置新属性名（tag_name参数）以及属性值（match_tag参数和not_match_tag参数），如果匹配则添加该属性值，否则添加另一个属性值;
-- 5. 支持配置日志输出文件路径（path参数）以及日志格式（log_format参数）；
-- 6. 支持配置是否输出请求响应体（include_resp_body参数）；
-- 7. 支持配置是否包含请求体（include_req_body参数），只有在配置了记录响应体时本插件的增强功能才会生效；
--

local log_util     =   require("apisix.utils.log-util")
local core         =   require("apisix.core")
local expr         =   require("resty.expr.v1")
local ngx          =   ngx
local io_open      =   io.open
local is_apisix_or, process = pcall(require, "resty.apisix.process")

-- 编码标记日志插件
local plugin_name = "code-tagger-logger"

local schema = {
    type = "object",
    properties = {
        path = {  type = "string" },
        log_format = {type = "object"},
        include_req_body = {type = "boolean", default = false},
        include_req_body_expr = {
            type = "array",
            minItems = 1,
            items = {
                type = "array"
            }
        },
        include_resp_body = {type = "boolean", default = true},
        code_name = {
            type = "string",
            default = "code"
        },
        code_values = {
            type = "array",
            items = {
                anyOf = {
                    {type = "integer"},
                    {type = "string"}
                }
            },
            maxItems = 20,
            default = { 0, -3, -5, -7, -10 }
        },
        tag_name = { type = "string", default = "code_tag", description = "计费标识属性名称" },
        value_name = { type = "string", default = "code_value", description = "原始编码值属性名称" },
        match_tag = { type = "integer", default = 1, description = "计费标识值" },
        not_match_tag = { type = "integer", default = 0, description = "不计费标识值" },
        none_match = { type = "integer", default = 9, description = "未成功匹配标识值" },
        enable_code_match = { type = "boolean", default = true, description = "是否开启响应体编码值匹配" }
    },
    required = {"path"}
}


local metadata_schema = {
    type = "object",
    properties = {
        log_format = {
            type = "object"
        }
    }
}


local _M = {
    version = 0.4,
    priority = 99,
    name = plugin_name,
    schema = schema,
    metadata_schema = metadata_schema
}


function _M.check_schema(conf, schema_type)
    if schema_type == core.schema.TYPE_METADATA then
        return core.schema.check(metadata_schema, conf)
    end
    if conf.match then
        local ok, err = expr.new(conf.match)
        if not ok then
            return nil, "failed to validate the 'match' expression: " .. err
        end
    end
    return core.schema.check(schema, conf)
end


local open_file_cache
if is_apisix_or then
    -- TODO: switch to a cache which supports inactive time,
    -- so that unused files would not be cached
    local path_to_file = core.lrucache.new({
        type = "plugin",
    })

    local function open_file_handler(conf, handler)
        local file, err = io_open(conf.path, 'a+')
        if not file then
            return nil, err
        end

        -- it will case output problem with buffer when log is larger than buffer
        file:setvbuf("no")

        handler.file = file
        handler.open_time = ngx.now() * 1000
        return handler
    end

    function open_file_cache(conf)
        local last_reopen_time = process.get_last_reopen_ms()

        local handler, err = path_to_file(conf.path, 0, open_file_handler, conf, {})
        if not handler then
            return nil, err
        end

        if handler.open_time < last_reopen_time then
            core.log.notice("reopen cached log file: ", conf.path)
            handler.file:close()

            local ok, err = open_file_handler(conf, handler)
            if not ok then
                return nil, err
            end
        end

        return handler.file
    end
end


local function write_file_data(conf, log_message)
    local msg = core.json.encode(log_message)

    local file, err
    if open_file_cache then
        file, err = open_file_cache(conf)
    else
        file, err = io_open(conf.path, 'a+')
    end

    if not file then
        core.log.error("failed to open file: ", conf.path, ", error info: ", err)
    else
        -- file:write(msg, "\n") will call fwrite several times
        -- which will cause problem with the log output
        -- it should be atomic
        msg = msg .. "\n"
        -- write to file directly, no need flush
        local ok, err = file:write(msg)
        if not ok then
            core.log.error("failed to write file: ", conf.path, ", error info: ", err)
        end

        -- file will be closed by gc, if open_file_cache exists
        if not open_file_cache then
            file:close()
        end
    end
end

function _M.access(conf, ctx)
    -- change the code_values to hash table
    if not conf.code_hash then
        conf.code_hash = {}
        for _, v in ipairs(conf.code_values) do
            -- both integer and string are supported
            conf.code_hash[v] = true
            conf.code_hash[tostring(v)] = true
        end
    end
end

function _M.body_filter(conf, ctx)
    log_util.collect_body(conf, ctx)
end

-- 从指定位置反向找到合法首字节位置
local function find_valid_start_byte(str, pos)
    while pos > 0 do
        local b = str:byte(pos)
        -- 首字节需满足 UTF-8 规则
        if (b >= 0x00 and b <= 0x7F) or          -- 1字节
                (b >= 0xC2 and b <= 0xDF) or     -- 2字节
                (b >= 0xE0 and b <= 0xEF) or     -- 3字节
                (b >= 0xF0 and b <= 0xF4) then   -- 4字节
            return pos
        end
        pos = pos - 1
    end
    return 0
end

local function validate_sequence(str, start_pos)
    local b = str:byte(start_pos)
    local required_follow = 0

    -- 严格遵循 UTF-8 首字节规范
    if b >= 0xF0 and b <= 0xF4 then       -- 4字节字符（修正范围）
        required_follow = 3
    elseif b >= 0xE0 and b <= 0xEF then   -- 3字节字符
        required_follow = 2
    elseif b >= 0xC2 and b <= 0xDF then   -- 2字节字符（修正范围）
        required_follow = 1
    elseif b <= 0x7F then                 -- 1字节 ASCII
        required_follow = 0
    else                                  -- 非法首字节（如 0x80-0xBF）
        return false, 0
    end

    -- 检查后续字节合法性
    for i = 1, required_follow do
        local pos = start_pos + i
        if pos > #str then return false, 0 end
        local fb = str:byte(pos)
        if fb < 0x80 or fb > 0xBF then   -- 必须为 10xxxxxx
            return false, 0
        end
    end
    return true, (required_follow + 1)  -- 总字节数 = 首字节 + 后续字节数
end

local function safe_truncate_utf8(str)
    if not str or str == "" then return str end
    local max_pos = #str

    -- 反向查找合法字符边界
    while max_pos > 0 do
        -- 找到有效首字节位置（避免从中间字节开始）
        local start_pos = find_valid_start_byte(str, max_pos)
        if start_pos == 0 then break end

        -- 验证字符完整性并获取总字节数
        local is_valid, char_length = validate_sequence(str, start_pos)
        if is_valid then
            return str:sub(1, start_pos + char_length - 1)  -- 截取完整字符
        else
            max_pos = start_pos - 1  -- 向前回溯
        end
    end
    return ""
end

-- Function to resolve JSON paths using dot notation (e.g. "data.bizCode")
local function get_nested_value(json_obj, path)
    if not path or path == "" then
        return json_obj
    end

    -- Split path by dots
    local keys = {}
    for key in string.gmatch(path, "[^%.]+") do
        table.insert(keys, key)
    end

    local current = json_obj
    for _, key in ipairs(keys) do
        if current and type(current) == "table" then
            current = current[key]
        else
            -- Path doesn't exist, return not_match_tag as per spec
            return nil
        end
    end

    return current
end

function _M.log(conf, ctx)
    local entry = log_util.get_log_entry(plugin_name, conf, ctx)
    if entry == nil then
        return
    end
    -- the default tag is not match
    local tag = conf.not_match_tag

    -- 增加变量用于存储找到的原始值
    local found_val = nil

    -- 只在开启编码匹配「enable_code_match」时，才解析响应体做编码匹配；
    -- 否则直接使用默认的 not_match_tag 值标记该调用为非计费日志
    if conf.enable_code_match then
        if ngx.status == 200 then
            -- check if response body is json format
            local code_resp_json = 0
            local success, json_parse = pcall(core.json.decode, ctx.resp_body or "")
            if success and json_parse then
                code_resp_json = 1
                -- Use the get_nested_value function to handle both simple and nested paths
                local extracted_value = get_nested_value(json_parse, conf.code_name)

                if extracted_value ~= nil then
                    found_val = extracted_value
                    -- check if extracted value is in the code_values list
                    if conf.code_hash[extracted_value] then
                        -- if matched, set the tag to match
                        tag = conf.match_tag
                    end
                else
                    -- If the path doesn't exist in valid JSON, set code_name parameter value to not_match_tag (as per spec)
                    tag = conf.not_match_tag
                end
            else
                -- if response body is too huge, fast truncate string in utf8 encoding
                if ctx.resp_body and entry.response.body then
                    entry.response.body = safe_truncate_utf8(entry.response.body);
                end
                -- other data format, use regex to match
                -- Example (conf.code_name="code"):
                -- PCRE2 Regex: /(,|{)\s*\\?"code\\?"\s*:\s*(?:\\?"(.*?)\\?"|(-?\d+))\s*(,|})/
                --       ResponseBody: [,\"code\":0,] OR [,\"code\":"0",] OR [,\"code\":\"0\",]
                -- Note: For malformed JSON, this regex will not work properly as it expects a JSON format
                -- [V0.3] 升级正则逻辑，支持匹配数字或双引号包裹的字符串
                -- pattern logic:
                -- 1. match key: handles both "key" and \"key\" (escaped)
                -- 2. match value: handles both "string" and \"string\" (escaped) AND integers
                -- Regex breakdown:
                -- \\? matches optional backslash (for escaped quotes)
                -- (?:"([^"]*)"|(-?\d+)) updated to allow optional escaped quotes around string values
                local pattern = [[(,|{)\s*\\?"]] .. conf.code_name .. [[\\?"\s*:\s*(?:\\?"(.*?)\\?"|(-?\d+))\s*(,|})]]
                local m, err = ngx.re.match((ctx.resp_body or ""), pattern, "jo")
                if m then
                    -- m[2] is the string content (without quotes), m[3] is the integer
                    local code_value = m[2] or m[3] or ""
                    found_val = code_value

                    local is_match = conf.code_hash[code_value] or false
                    core.log.info("resp code value: " .. code_value .. ", resp code match: " .. tostring(is_match))
                    if is_match then
                        tag = conf.match_tag
                    end
                else
                    -- if response body is malformed JSON or not valid JSON, and cant find the schema by regex, set the tag to none_match
                    tag = conf.none_match
                end
            end
            -- set the code_resp_json to log entry
            entry.code_resp_json = code_resp_json
        end
    end

    -- set the tag to log entry
    entry[conf.tag_name] = tag
    -- 将当前 match_enabled 状态显式写入日志，便于排查与对账（true为1，false为0）
    entry.match_enabled = conf.enable_code_match and 1 or 0

    -- 将找到的编码实际值写入日志（如果存在）
    if found_val ~= nil then
        entry[conf.value_name] = found_val
    end

    write_file_data(conf, entry)
end


return _M
