--
-- 九章数盾API-请求签名支持插件
-- 特性说明：
-- 1. 请求方式：POST-JSON请求体提交方式(Method: POST, Content-Type: application/json)
-- 2. 加密算法：SM4 (FFI实现方式)，Adapted from Toruneko's lua-resty-sm4 (FFI optimized)
-- v0.1 (2026/02/03)
--
local core = require("apisix.core")
local json = require("apisix.core.json")
local hmac = require("resty.openssl.hmac")
local rand = require("resty.random")
local str_util = require("resty.string")
local bit = require("bit")
local ffi = require("ffi")

local bor = bit.bor
local band = bit.band
local bxor = bit.bxor
local lshift = bit.lshift
local rshift = bit.rshift
local ffi_new = ffi.new
local ffi_cast = ffi.cast
local ffi_str = ffi.string

-- Localize the OpenResty method for performance and availability
local req_set_body_data = ngx.req.set_body_data
local ngx_encode_base64 = ngx.encode_base64

local schema = {
    type = "object",
    properties = {
        version = { type = "string", default = "V1.0.0" },
        app_id = { type = "string" },
        biz_type = { type = "string" },
        app_key = { type = "string", minLength = 16 }
    },
    required = { "app_id", "biz_type", "app_key" }
}

local _M = {
    version = 0.1,
    priority = 2501,
    name = "9zsd-api",
    schema = schema,
}

-- ==========================================================================
-- Copyright (C) by Jianhao Dai (Toruneko)
-- SM4 FFI Implementation (Standard GM/T 0002-2012)
-- ==========================================================================
-- Define C types for fast memory access
local uint32_ptr = ffi.typeof("uint32_t[?]")
local uint32_arr4 = ffi.typeof("uint32_t[4]")

-- System Parameters
local FK = ffi_new("const uint32_t[4]", { 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC })
local CK = ffi_new("const uint32_t[32]", {
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269, 0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249, 0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229, 0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209, 0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
})
local Sbox = ffi_new("const uint32_t[256]", {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
})

-- Helpers for Byte/Int conversion
local function get32(s, i)
    local b1, b2, b3, b4 = string.byte(s, i, i+3)
    return bor(lshift(b1, 24), lshift(b2, 16), lshift(b3, 8), b4)
end
local function put32(n, t, i)
    t[i] = band(rshift(n, 24), 0xFF)
    t[i+1] = band(rshift(n, 16), 0xFF)
    t[i+2] = band(rshift(n, 8), 0xFF)
    t[i+3] = band(n, 0xFF)
end

-- SM4 Core Transforms
local function S_rot(x, n) return bor(lshift(x, n), rshift(x, 32 - n)) end
local function P(a)
    return bor(lshift(Sbox[rshift(a, 24)], 24), lshift(Sbox[band(rshift(a, 16), 0xFF)], 16), lshift(Sbox[band(rshift(a, 8), 0xFF)], 8), Sbox[band(a, 0xFF)])
end
local function L(b) return bxor(b, S_rot(b, 2), S_rot(b, 10), S_rot(b, 18), S_rot(b, 24)) end
local function T(a) return L(P(a)) end
local function F(x0, x1, x2, x3, rk) return bxor(x0, T(bxor(x1, x2, x3, rk))) end
local function L_prime(b) return bxor(b, S_rot(b, 13), S_rot(b, 23)) end
local function T_prime(a) return L_prime(P(a)) end
local function F_prime(x0, x1, x2, x3, rk) return bxor(x0, T_prime(bxor(x1, x2, x3, rk))) end

-- Key Expansion
local function sm4_set_key(key_bytes)
    local K = ffi_new(uint32_arr4)
    K[0] = bxor(get32(key_bytes, 1), FK[0])
    K[1] = bxor(get32(key_bytes, 5), FK[1])
    K[2] = bxor(get32(key_bytes, 9), FK[2])
    K[3] = bxor(get32(key_bytes, 13), FK[3])
    local rk = ffi_new(uint32_ptr, 32)
    for i = 0, 7 do
        local j = 4 * i
        K[0] = F_prime(K[0], K[1], K[2], K[3], CK[j])
        K[1] = F_prime(K[1], K[2], K[3], K[0], CK[j+1])
        K[2] = F_prime(K[2], K[3], K[0], K[1], CK[j+2])
        K[3] = F_prime(K[3], K[0], K[1], K[2], CK[j+3])
        rk[j], rk[j+1], rk[j+2], rk[j+3] = K[0], K[1], K[2], K[3]
    end
    return rk
end

-- Single Block Crypt
local function sm4_crypt_block(rk, input_bytes)
    local X = ffi_new(uint32_arr4)
    X[0] = get32(input_bytes, 1)
    X[1] = get32(input_bytes, 5)
    X[2] = get32(input_bytes, 9)
    X[3] = get32(input_bytes, 13)
    for i = 0, 7 do
        local j = 4 * i
        X[0] = F(X[0], X[1], X[2], X[3], rk[j])
        X[1] = F(X[1], X[2], X[3], X[0], rk[j+1])
        X[2] = F(X[2], X[3], X[0], X[1], rk[j+2])
        X[3] = F(X[3], X[0], X[1], X[2], rk[j+3])
    end
    local out_buf = ffi_new("uint8_t[16]")
    put32(X[3], out_buf, 0)
    put32(X[2], out_buf, 4)
    put32(X[1], out_buf, 8)
    put32(X[0], out_buf, 12)
    return ffi_str(out_buf, 16)
end

-- PKCS7 Padding
local function pkcs7_pad(data)
    local pad_len = 16 - (#data % 16)
    return data .. string.rep(string.char(pad_len), pad_len)
end

-- Common Helpers
local function to_hex(str) return str_util.to_hex(str) end
local function from_hex(str)
    return (str:gsub('..', function (cc) return string.char(tonumber(cc, 16)) end))
end
local function generate_factor() return rand.bytes(8) end
local function xor_with_ff(bytes_str)
    local t = {}
    for i = 1, #bytes_str do
        table.insert(t, string.char(bxor(string.byte(bytes_str, i), 0xFF)))
    end
    return table.concat(t)
end

-- ==========================================================================
-- Business Logic
-- ==========================================================================

-- 1. Derive Key (ECB Mode)
-- Input: appKey16 (Raw Bytes), factor8 (Raw Bytes)
-- Logic: Plain = factor8 || (factor8 ^ FF)
--        Result = SM4_ECB(appKey16, Plain)
local function derive_key(app_key, factor_bytes)
    if not app_key then return nil end

    -- Construct 16-byte plain block: X || (X ^ FF)
    local input_block = factor_bytes .. xor_with_ff(factor_bytes)

    local key_spec = app_key:gsub("%s+", "")
    -- Decode 32-char Hex App Key to 16-byte Binary
    if #key_spec == 32 and key_spec:match("^[0-9a-fA-F]+$") then
        key_spec = from_hex(key_spec)
    end

    if #key_spec ~= 16 then
        core.log.error("derive_key: Invalid key length ", #key_spec)
        return nil
    end

    local rk = sm4_set_key(key_spec)
    return sm4_crypt_block(rk, input_block)
end

-- 2. Encrypt Data (CBC Mode)
-- Logic:
--   1. Generate Random IV (16 bytes)
--   2. Encrypt Padded Data with CBC
--   3. Result = IV || CipherText
local function encrypt_sm4_cbc(data, key)
    if #key ~= 16 then return nil end

    local padded_data = pkcs7_pad(data)
    local rk = sm4_set_key(key)

    -- 1. Generate Random 16-byte IV
    local iv = rand.bytes(16)
    local current_iv = iv -- Used for chaining in loop

    local output_blocks = {}

    -- 2. Encrypt
    for i = 1, #padded_data, 16 do
        local block = string.sub(padded_data, i, i+15)
        local xored = {}
        for j = 1, 16 do
            local b_in = string.byte(block, j)
            local b_iv = string.byte(current_iv, j)
            table.insert(xored, string.char(bxor(b_in, b_iv)))
        end
        local cipher_block = sm4_crypt_block(rk, table.concat(xored))
        table.insert(output_blocks, cipher_block)
        current_iv = cipher_block -- Update IV for next block (CBC)
    end

    -- 3. Result = IV || CipherText
    local binary_result = iv .. table.concat(output_blocks)
    return ngx_encode_base64(binary_result)
end

local function sort_and_serialize(t)
    local keys = {}
    for k in pairs(t) do table.insert(keys, k) end
    table.sort(keys)
    local parts = {}
    for _, k in ipairs(keys) do
        local v = t[k]
        local val_str = ""
        if type(v) == "table" then val_str = sort_and_serialize(v) else val_str = tostring(v) end
        if val_str and val_str ~= "" then table.insert(parts, k .. "=" .. val_str) end
    end
    return table.concat(parts, "&")
end

function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

function _M.rewrite(conf, ctx)
    -- 0.幂等性处理，避免重复执行
    if ctx._9zsd_executed then return end

    -- 1. Filter request method AND content-type
    if core.request.get_method() ~= "POST" then return 405 end
    local ct = core.request.header(ctx, "Content-Type")
    if not ct or not string.find(ct, "application/json", 1, true) then return 400 end

    local req_body, err = core.request.get_body()
    if not req_body then return 400 end
    local success, body_json = pcall(core.json.decode, req_body)
    if not success or type(body_json) ~= "table" then return 400 end

    -- Generate Factors (Raw 8 Bytes)
    local encrypt_factor_bytes = generate_factor()
    local sign_factor_bytes = generate_factor()

    -- Hex encoded factors for JSON response
    local security_factor = {
        encrypt_factor = to_hex(encrypt_factor_bytes),
        sign_factor = to_hex(sign_factor_bytes)
    }

    -- Derive Keys (Pass Raw Bytes)
    local Ke = derive_key(conf.app_key, encrypt_factor_bytes)
    local Ks = derive_key(conf.app_key, sign_factor_bytes)

    if not Ke or not Ks then return 500 end

    -- Encrypt
    if body_json.bparams then
        local bparams_str = body_json.bparams
        if type(bparams_str) == "table" then bparams_str = json.encode(bparams_str) end
        local enc_bparams = encrypt_sm4_cbc(bparams_str, Ke)
        if not enc_bparams then
            core.log.error("Failed to encrypt bparams")
            return 500
        end
        body_json.bparams = enc_bparams
    end

    -- Inject
    body_json.version = conf.version
    body_json.app_id = conf.app_id
    body_json.biz_type = conf.biz_type
    body_json.biz_time = tostring(os.date("%Y%m%d%H%M%S"))
    body_json.encrypt_type = "2" -- String type as per previous confirmation
    body_json.sign_type = "2"
    body_json.security_factor = security_factor

    -- Sign
    local sign_data_map = core.table.clone(body_json)
    sign_data_map.sign = nil
    local string_to_sign = sort_and_serialize(sign_data_map)

    local hmac_sha256 = hmac.new(Ks, "sha256")
    hmac_sha256:update(string_to_sign)
    -- Use Base64 for Signature (matches Java SignUtil)
    local sign_result = ngx_encode_base64(hmac_sha256:final())
    body_json.sign = sign_result

    local new_body_json_string = core.json.encode(body_json)
    req_set_body_data(new_body_json_string)
    core.log.info("new body json:", new_body_json_string)

    -- 设置标志位，表示已成功执行，避免多次执行
    ctx._9zsd_executed = true
end

return _M
