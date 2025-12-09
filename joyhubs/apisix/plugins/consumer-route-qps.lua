--
-- 消费者路由 QPS 限流插件（consumer-route-qps）
-- 说明: Consumer + Route level QPS rate limiting (Leaky Bucket) backed by Redis atomic scripts.
--
local core = require("apisix.core")
local redis = require("apisix.utils.redis")
local redis_cluster = require("apisix.utils.rediscluster")
local ngx_now = ngx.now
local sleep = core.sleep
local plugin_name = "consumer-route-qps"

-- Default Schema
local schema = {
    type = "object",
    properties = {
        -- 1. Redis Policy Selection
        policy = {
            type = "string",
            enum = { "redis", "redis-cluster" },
            default = "redis"
        },

        -- 2. Redis Connection Config
        redis_host = { type = "string", minLength = 1 },
        redis_port = { type = "integer", minimum = 1, default = 6379 },
        redis_database = { type = "integer", minimum = 0, default = 0 },
        redis_username = { type = "string", minLength = 1 },
        redis_password = { type = "string", minLength = 0 },
        redis_timeout = { type = "integer", minimum = 1, default = 1000 },
        redis_ssl = { type = "boolean", default = false },
        redis_ssl_verify = { type = "boolean", default = false },

        redis_cluster_nodes = {
            type = "array",
            minItems = 2,
            items = { type = "string", minLength = 2 }
        },
        redis_cluster_ssl = { type = "boolean", default = false },
        redis_cluster_ssl_verify = { type = "boolean", default = false },

        -- 3. Rate Limit Config
        -- 默认速率（QPS），设置为 0 表示不限制
        default_rate = { type = "number", minimum = 0 },
        -- 默认突发大小
        default_burst = { type = "number", minimum = 0 },

        -- 是否立即处理突发流量
        nodelay = { type = "boolean", default = false },

        -- 4. Dynamic Quota Map
        consumer_quotas = {
            type = "object",
            patternProperties = {
                ["^.+$"] = {
                    type = "object",
                    properties = {
                        rate = { type = "number", exclusiveMinimum = 0 },
                        burst = { type = "number", minimum = 0 }
                    },
                    required = { "rate" }
                }
            }
        },

        key_prefix = { type = "string", default = "dvc:qps:" },
        allow_degradation = { type = "boolean", default = true },
        show_limit_quota_header = { type = "boolean", default = true },
        rejected_code = { type = "integer", minimum = 200, maximum = 599, default = 429 },
        rejected_msg = { type = "string", minLength = 1 }
    },

    required = { "redis_password" },
    ["if"] = {
        properties = { policy = { const = "redis-cluster" } },
        -- 默认值也能触发校验
        required = { "policy" }
    },
    ["then"] = {
        required = { "redis_cluster_nodes" }
    },
    ["else"] = {
        required = { "redis_host" }
    }
}

local _M = {
    version = 0.1,
    priority = 1006,
    name = plugin_name,
    schema = schema,
}

-- Redis Atomic Leaky Bucket Script
local script = core.string.compress_script([=[
    local excess_key = KEYS[1]
    local last_key = KEYS[2]
    local rate = tonumber(ARGV[1])
    local burst = tonumber(ARGV[2])
    local now = tonumber(ARGV[3])
    local cost = tonumber(ARGV[4]) or 1

    local excess = tonumber(redis.call('get', excess_key))
    local last = tonumber(redis.call('get', last_key))

    if excess and last then
        -- 1. Calculate leaked amount
        local elapsed = math.max(0, now - last)
        local leaked = (elapsed / 1000) * rate

        -- 2. Update excess (drain the bucket)
        excess = math.max(0, excess - leaked)
    else
        -- First time access
        excess = 0
    end

    -- 3. Check burst (Crucial Fix: Check BEFORE adding cost)
    -- If the *existing* excess is already greater than burst, we reject.
    -- This allows the first request (excess=0) to pass even if burst=0.
    if excess > burst then
        return -1 -- Rejected
    end

    -- 4. Update state (fill the bucket)
    excess = excess + cost

    local ttl = 60000

    redis.call('set', excess_key, excess, 'PX', ttl)
    redis.call('set', last_key, now, 'PX', ttl)

    -- Return current excess level
    return excess
]=])

function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

local function gen_keys(conf, ctx)
    local consumer_name = ctx.consumer_name or "anonymous"
    local route_id = ctx.route_id or ctx.var.uri
    -- Hash Tag
    local base_key = "{" .. conf.key_prefix .. consumer_name .. ":" .. route_id .. "}"
    return base_key .. ":excess", base_key .. ":last", consumer_name
end

local function get_limit_config(conf, consumer_name)
    local specific = conf.consumer_quotas and conf.consumer_quotas[consumer_name]
    if specific then
        return specific.rate, (specific.burst or specific.rate)
    end
    if conf.default_rate and conf.default_rate > 0 then
        return conf.default_rate, (conf.default_burst or conf.default_rate)
    end
    return nil, nil
end

local function get_redis_client(conf)
    if conf.policy == "redis-cluster" then
        if conf.redis_password and conf.redis_password ~= "" then
            conf.auth = conf.redis_password
        end
        if conf.redis_cluster_ssl then
            conf.ssl = true
        end
        if conf.redis_cluster_ssl_verify then
            conf.ssl_verify = true
        end
        return redis_cluster.new(conf, "plugin-limit-req-redis-cluster-slot-lock")
    else
        return redis.new(conf)
    end
end

function _M.access(conf, ctx)
    local excess_key, last_key, consumer_name = gen_keys(conf, ctx)
    local rate, burst = get_limit_config(conf, consumer_name)

    if not rate then
        return
    end

    local red, err = get_redis_client(conf)
    if not red then
        if conf.allow_degradation then
            return
        end
        return 500, { error_msg = "Internal QPS Limit Error" }
    end

    local current_ms = ngx_now() * 1000

    -- Execute Script
    local res, err = red:eval(script, 2, excess_key, last_key, rate, burst, current_ms, 1)

    if err then
        if conf.allow_degradation then
            return
        end
        return 500, { error_msg = "Internal QPS Limit Error" }
    end

    -- Release connection
    if red.set_keepalive then
        red:set_keepalive(10000, 100)
    end

    local excess = res

    -- 1. Handle Rejection
    if excess == -1 then
        if conf.show_limit_quota_header then
            core.response.set_header("X-RateLimit-Limit", rate)
            core.response.set_header("X-RateLimit-Remaining", 0)
        end

        if conf.rejected_msg then
            return conf.rejected_code, { error_msg = conf.rejected_msg }
        end
        return conf.rejected_code
    end

    -- 2. Handle Traffic Shaping (Sleep)
    -- 计算需要等待的时间： Delay = (Excess - 1) / Rate
    if not conf.nodelay then
        -- 当前请求需要等待的时间，是排在它前面的请求漏完所需的时间
        -- 前面的积压量 = excess - 1
        local latency_excess = math.max(0, excess - 1)
        local delay = latency_excess / rate

        if delay >= 0.001 then
            sleep(delay)
        end
    end

    -- 3. Set Headers
    if conf.show_limit_quota_header then
        core.response.set_header("X-RateLimit-Limit", rate)
        -- Remaining: Available Burst (Burst - Current Excess)
        local remaining = math.floor(math.max(0, burst - excess))
        core.response.set_header("X-RateLimit-Remaining", remaining)
    end
end

return _M
