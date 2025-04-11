---
--- test utils/utf8_toolkit.lua
--- @author joyhubs
---
local utf8_toolkit = require("utils.utf8_toolkit")

local hello_world_bytes = {
    0xE4, 0xBD, 0xA0, -- "你"
    0xE5, 0xA5, 0xBD, -- "好"
    0xEF, 0xBC, 0x8C, -- "，"
    0xE4, 0xB8, 0x96, -- "世"
    0xE7, 0x95, 0x8C   -- "界"
}
local str = string.char(table.unpack(hello_world_bytes))
print("sample: " .. str)

-- incomplete utf8 string: [你好，世界]
local hello_world_str = "\xE4\xBD\xA0\xE5\xA5\xBD\xEF\xBC\x8C\xE4\xB8\x96\xE7\x95"
print("incomplete sample: " .. hello_world_str)

-- truncate the incomplete utf8 string
local truncated_str = utf8_toolkit.safe_truncate_utf8(hello_world_str)
print(truncated_str)

local truncated_str2 = utf8_toolkit.fast_truncate_utf8(hello_world_str)
print(truncated_str2)


