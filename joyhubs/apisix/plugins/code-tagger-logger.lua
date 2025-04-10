--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
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
            items = { type = "integer" },
            maxItems = 20,
            default = { 0, -3, -5, -7, -10 }
        },
        tag_name = { type = "string", default = "code_tag" },
        match_tag = { type = "integer", default = 1 },
        not_match_tag = { type = "integer", default = 0 }
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
    version = 0.1,
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

function _M.log(conf, ctx)
    local entry = log_util.get_log_entry(plugin_name, conf, ctx)
    if entry == nil then
        return
    end
    -- the default tag is not match
    local tag = conf.not_match_tag
    if ngx.status == 200 then
        -- check if response body is json format
        local code_resp_json = 0
        local json_body = core.json.decode(ctx.resp_body or "")
        -- check if response body contains code field
        if json_body and json_body[conf.code_name] then
            code_resp_json = 1
            -- check if code value is in the code_values list
            if conf.code_hash[json_body[conf.code_name]] then
                -- if matched, set the tag to match
                tag = conf.match_tag
            end
        else
            -- if response body is too huge, fast truncate string in utf8 encoding
            if ctx.resp_body and entry.response.body then
                entry.response.body = safe_truncate_utf8(entry.response.body);
            end
            -- other data format, use regex to match, PCRE regex example: [[(,|{)\s*\\?"code\\?"\s*:\s*(-?\d+)\s*(,|})]]
            -- example response body: `,\"code\":0,`
            local pattern = [[(,|{)\s*\\?"]] .. conf.code_name .. [[\\?"\s*:\s*(-?\d+)\s*(,|})]]
            local m, err = ngx.re.match((ctx.resp_body or ""), pattern, "jo")
            if m then
                local code_value = m[2] or ""
                local is_match = conf.code_hash[code_value] or false
                core.log.info("resp code value: " .. code_value .. ", resp code match: " .. tostring(is_match))
                if is_match then
                    tag = conf.match_tag
                end
            end
        end
        -- set the code_resp_json to log entry
        entry.code_resp_json = code_resp_json
    end
    -- set the tag to log entry
    entry[conf.tag_name] = tag

    write_file_data(conf, entry)
end


return _M
