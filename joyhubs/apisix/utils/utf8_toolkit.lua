---
--- utf8 string toolkit
--- @author green
--- DateTime: 2025/4/11 11:54

local utf8_toolkit = {}

---
--- 截除尾部不完整的 UTF-8 字符字节数据（通过Lua 5.3版本utf8库实现）
---@overload fun(s:string):string
---@param s string
---@return string
function utf8_toolkit.fast_truncate_utf8(s)
    if not s or s == "" then
        return s
    end
    -- utf8.len 返回 nil 和出错位置（第一个非法字节的位置）
    -- 如果返回数字，则说明整个字符串都是合法的 UTF-8。
    local n, pos = utf8.len(s)
    if n then
        -- 完全合法，无需修剪
        return s
    else
        -- pos 为第一个检测到错误的字节下标，trim 掉从该位置开始的内容
        return s:sub(1, pos - 1)
    end
end

---
-- 从指定位置反向找到合法首字节位置
local function find_valid_start_byte(str, pos)
    while pos > 0 do
        local b = str:byte(pos)
        -- 首字节需满足 UTF-8 规则
        if (b >= 0x00 and b <= 0x7F) or -- 1字节
                (b >= 0xC2 and b <= 0xDF) or -- 2字节
                (b >= 0xE0 and b <= 0xEF) or -- 3字节
                (b >= 0xF0 and b <= 0xF4) then
            -- 4字节
            return pos
        end
        pos = pos - 1
    end
    return 0
end

---
--- 验证 UTF-8 字符序列的合法性
local function validate_sequence(str, start_pos)
    local b = str:byte(start_pos)
    local required_follow = 0

    -- 严格遵循 UTF-8 首字节规范
    if b >= 0xF0 and b <= 0xF4 then
        -- 4字节字符（修正范围）
        required_follow = 3
    elseif b >= 0xE0 and b <= 0xEF then
        -- 3字节字符
        required_follow = 2
    elseif b >= 0xC2 and b <= 0xDF then
        -- 2字节字符（修正范围）
        required_follow = 1
    elseif b <= 0x7F then
        -- 1字节 ASCII
        required_follow = 0
    else
        -- 非法首字节（如 0x80-0xBF）
        return false, 0
    end

    -- 检查后续字节合法性
    for i = 1, required_follow do
        local pos = start_pos + i
        if pos > #str then
            return false, 0
        end
        local fb = str:byte(pos)
        if fb < 0x80 or fb > 0xBF then
            -- 必须为 10xxxxxx
            return false, 0
        end
    end
    return true, (required_follow + 1)  -- 总字节数 = 首字节 + 后续字节数
end

---
--- 截除尾部不完整的 UTF-8 字符字节数据（兼容Lua 5.1版本）
---@since Lua 5.3
---@overload fun(s:string):string
---@param str string
---@return string
function utf8_toolkit.safe_truncate_utf8(str)
    if not str or str == "" then
        return str
    end
    local max_pos = #str

    -- 反向查找合法字符边界
    while max_pos > 0 do
        -- 找到有效首字节位置（避免从中间字节开始）
        local start_pos = find_valid_start_byte(str, max_pos)
        if start_pos == 0 then
            break
        end

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

return utf8_toolkit
