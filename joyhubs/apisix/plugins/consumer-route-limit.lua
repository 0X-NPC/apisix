--
-- 消费者路由限流插件（consumer-route-limit）
-- 说明: Consumer Route level rate limiting with dynamic quotas (count & window) backed by Redis.
--
local core = require("apisix.core")
local redis = require("apisix.utils.redis")
local plugin_name = "consumer-route-limit"

-- Default Schema
local schema = {
    type = "object",
    properties = {
        -- 1. Redis Configuration
        redis_host = {type = "string", minLength = 1},
        redis_port = {type = "integer", minimum = 1, default = 6379},
        redis_password = {type = "string", minLength = 0},
        redis_database = {type = "integer", minimum = 0, default = 0},
        redis_timeout = {type = "integer", minimum = 1, default = 1000},

        -- 2. Global Default Configuration
        -- 默认时间窗口，单位：秒（当特定租户未配置窗口时使用）
        time_window = {type = "integer", minimum = 1, default = 60},
        -- 默认限制次数，允许配置 0 或 -1 表示不限制。
        default_count = {type = "integer", default = 0 },

        -- 3. Dynamic Quota Map
        -- consumer_name -> { count, time_window(optional) }
        consumer_quotas = {
            type = "object",
            patternProperties = {
                ["^.+$"] = {
                    type = "object",
                    properties = {
                        count = {type = "integer", minimum = 1},
                        time_window = {type = "integer", minimum = 1}
                    },
                    required = {"count"} -- 必须配置次数，窗口可选（默认继承全局）
                }
            }
        },

        -- 4. Key Configuration
        key_prefix = {type = "string", default = "dvc:crl:"},

        -- 5. Reliability
        allow_degradation = {type = "boolean", default = true},

        -- 6. Response Info, 429 (Too many requests)
        show_limit_quota_header = {type = "boolean", default = true},
        rejected_code = {type = "integer", minimum = 200, maximum = 599, default = 429},
        rejected_msg = {type = "string", minLength = 1}
    },
    -- HOTS、PASSWORD为必填项
    required = {"redis_host", "redis_password"}
}

local _M = {
    version = 0.1,
    priority = 1005,
    name = plugin_name,
    schema = schema,
}

-- Redis Atomic Script
local script = core.string.compress_script([=[
    local key = KEYS[1]
    local limit = tonumber(ARGV[1])
    local window = tonumber(ARGV[2])
    local cost = tonumber(ARGV[3])

    local ttl = redis.call('ttl', key)

    -- If key does not exist or expired
    if ttl < 0 then
        redis.call('set', key, limit - cost, 'EX', window)
        return {limit - cost, window}
    end

    -- If key exists, decrement
    local remaining = redis.call('incrby', key, 0 - cost)
    return {remaining, ttl}
]=])

function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

local function gen_key(conf, ctx)
    local consumer_name = ctx.consumer_name
    if not consumer_name then
        consumer_name = ctx.var.remote_addr or "anonymous"
    end

    local route_id = ctx.route_id or ctx.var.uri
    return conf.key_prefix .. consumer_name .. ":" .. route_id, consumer_name
end

-- 获取针对当前用户的配置（次数, 窗口）
-- 返回: count(number/nil), window(number/nil)
-- 如果 count 为 nil，表示不限制
local function get_limit_config(conf, consumer_name)
    -- 1. 优先查特定配置 (O(1) Map Lookup)
    local specific_conf = conf.consumer_quotas and conf.consumer_quotas[consumer_name]

    if specific_conf then
        -- 如果特定配置里没写 window，就用全局默认的 window
        local window = specific_conf.time_window or conf.time_window
        return specific_conf.count, window
    end

    -- 2. 回退到默认配置
    -- 逻辑：如果 default_count 存在且 > 0，则限制；否则（nil, 0, -1）不限制
    if conf.default_count and conf.default_count > 0 then
        return conf.default_count, conf.time_window
    end

    return nil, nil
end

function _M.access(conf, ctx)
    local limit_key, consumer_name = gen_key(conf, ctx)

    -- 获取动态配置
    local limit_count, limit_window = get_limit_config(conf, consumer_name)

    -- 如果 limit_count 为空，直接放行（default_count <= 0 不限制）
    if not limit_count then
        return
    end

    -- Core Logic
    local red, err = redis.new(conf)
    if not red then
        core.log.error("failed to connect redis: ", err)
        if conf.allow_degradation then return end
        return 500, {error_msg = "Internal Rate Limit Error"}
    end

    -- Execute Script with Dynamic Window
    local res, err = red:eval(script, 1, limit_key, limit_count, limit_window, 1)

    if err then
        core.log.error("failed to execute redis script: ", err)
        red:set_keepalive(10000, 100)
        if conf.allow_degradation then return end
        return 500, {error_msg = "Internal Rate Limit Error"}
    end

    local remaining = res[1]
    local ttl = res[2]

    local ok, err = red:set_keepalive(10000, 100)
    if not ok then
        core.log.warn("failed to set keepalive: ", err)
    end

    if conf.show_limit_quota_header then
        core.response.set_header("X-RateLimit-Limit", limit_count)
        core.response.set_header("X-RateLimit-Remaining", math.max(0, remaining))
        core.response.set_header("X-RateLimit-Reset", ttl)
    end

    if remaining < 0 then
        if conf.rejected_msg then
            return conf.rejected_code, { error_msg = conf.rejected_msg }
        end
        return conf.rejected_code
    end
end

return _M
