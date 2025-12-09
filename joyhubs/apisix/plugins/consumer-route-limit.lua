--
-- 消费者路由限流插件（consumer-route-limit）
-- 说明: Consumer Route level rate limiting with dynamic quotas (count & window) backed by Redis.
--
local core = require("apisix.core")
local redis = require("apisix.utils.redis")
local redis_cluster = require("apisix.utils.rediscluster")
local plugin_name = "consumer-route-limit"

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

        -- 2. Standalone Configuration (policy = "redis")
        redis_host = { type = "string", minLength = 1 },
        redis_port = { type = "integer", minimum = 1, default = 6379 },
        redis_database = { type = "integer", minimum = 0, default = 0 },
        redis_ssl = { type = "boolean", default = false },
        redis_ssl_verify = { type = "boolean", default = false },

        -- 3. Cluster Configuration (policy = "redis-cluster")
        redis_cluster_nodes = {
            type = "array",
            minItems = 2,
            items = {
                type = "string", minLength = 2, maxLength = 100
            }
        },
        redis_cluster_ssl = { type = "boolean", default = false },
        redis_cluster_ssl_verify = { type = "boolean", default = false },

        -- Redis Auth & Timeout
        -- Redis Username (用于 Redis ACL)
        redis_username = { type = "string", minLength = 1 },
        redis_password = { type = "string", minLength = 0 },
        redis_timeout = { type = "integer", minimum = 1, default = 1000 },

        -- 4. Global Default Configuration
        time_window = { type = "integer", minimum = 1, default = 60 },
        default_count = { type = "integer", default = 0 },

        -- 5. Dynamic Quota Map
        consumer_quotas = {
            type = "object",
            patternProperties = {
                ["^.+$"] = {
                    type = "object",
                    properties = {
                        count = { type = "integer", minimum = 1 },
                        time_window = { type = "integer", minimum = 1 }
                    },
                    required = { "count" }
                }
            }
        },

        -- 6. Key Configuration
        key_prefix = { type = "string", default = "dvc:crl:" },

        -- 7. Reliability
        allow_degradation = { type = "boolean", default = true },

        -- 8. Response Info
        show_limit_quota_header = { type = "boolean", default = true },
        -- 429 Too many requests
        rejected_code = { type = "integer", minimum = 200, maximum = 599, default = 429 },
        rejected_msg = { type = "string", minLength = 1 }
    },

    required = { "redis_password" },
    dependencies = {
        policy = {
            oneOf = {
                {
                    properties = {
                        policy = { const = "redis-cluster" },
                        redis_cluster_nodes = { minItems = 2 }
                    },
                    required = { "redis_cluster_nodes" }
                },
                {
                    properties = {
                        policy = { const = "redis" },
                        redis_host = { minLength = 1 }
                    },
                    required = { "redis_host" }
                }
            }
        }
    }
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

-- 获取 Redis 客户端（支持单机和集群，含 SSL 处理）
local function get_redis_client(conf)
    if conf.policy == "redis-cluster" then
        -- 集群模式
        -- 1. 映射密码
        if conf.redis_password and conf.redis_password ~= "" then
            conf.auth = conf.redis_password
        end
        -- 2. 映射 SSL 配置，确保底层驱动能识别
        if conf.redis_cluster_ssl then
            conf.ssl = true
        end
        if conf.redis_cluster_ssl_verify then
            conf.ssl_verify = true
        end
        -- 注意：复用了官方limit-count插件定义的dict_name
        return redis_cluster.new(conf, "plugin-limit-count-redis-cluster-slot-lock")
    else
        -- 单机模式
        -- apisix.utils.redis 内部会自动处理 redis_ssl, redis_ssl_verify 以及 redis_username
        return redis.new(conf)
    end
end

function _M.access(conf, ctx)
    local limit_key, consumer_name = gen_key(conf, ctx)

    -- 获取动态配置
    local limit_count, limit_window = get_limit_config(conf, consumer_name)

    -- 如果 limit_count 为空，直接放行（default_count <= 0 不限制）
    if not limit_count then
        return
    end

    -- Core Logic: Get Client
    local red, err = get_redis_client(conf)
    if not red then
        if conf.allow_degradation then
            return
        end
        return 500, { error_msg = "Internal Rate Limit Error" }
    end

    -- Execute Script with Dynamic Window
    local res, err = red:eval(script, 1, limit_key, limit_count, limit_window, 1)

    if err then
        if conf.allow_degradation then
            return
        end
        return 500, { error_msg = "Internal Rate Limit Error" }
    end

    local remaining = res[1]
    local ttl = res[2]

    -- 单机/主从Redis需要通过set_keepalive主动释放连接
    if red.set_keepalive then
        red:set_keepalive(10000, 100)
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
