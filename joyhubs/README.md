---
title: code-tagger-logger
keywords:
  - APISIX
  - API 网关
  - Plugin
  - code-tagger-logger
description: API 网关 Apache APISIX code-tagger-logger 插件可用于接口响应中业务编码的匹配，并输出标签到请求日志文件。
---

<!--
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
-->

## 描述

`code-tagger-logger` 插件可用于接口响应中业务编码的匹配，并输出标签到请求日志文件。

:::tip 提示

`code-tagger-logger` 插件特点如下：

- 按照JSON格式解析接口响应结果，生成`code_resp_json`属性到日志中，解析成功为1，解析失败为0。
- 匹配响应结果中指定的业务编码，并生成匹配结果标签，输出到日志文件中。
- 可将指定路由的日志发送到指定位置，方便你在本地统计各个路由的请求和响应数据。在使用 [debug mode](../../../en/latest/debug-mode.md) 时，你可以很轻松地将出现问题的路由的日志输出到指定文件中，从而更方便地排查问题。
- 可以获取 [APISIX 变量](../../../en/latest/apisix-variable.md)和 [NGINX 变量](http://nginx.org/en/docs/varindex.html)，而 `access.log` 仅能使用 NGINX 变量。
- 支持热加载，你可以在路由中随时更改其配置并立即生效。而修改 `access.log` 相关配置，则需要重新加载 APISIX。
- 支持以 JSON 格式保存日志数据。
- 可以在 `log phase` 阶段修改 `code-tagger-logger` 执行的函数来收集你所需要的信息。

:::

## 属性

| 名称             | 类型      | 必选项 | 描述                                                                                                                                             |
| ---------------- |---------|---|------------------------------------------------------------------------------------------------------------------------------------------------|
| path             | string  | 是 | 自定义输出文件路径。例如：`logs/file.log`。                                                                                                                  |
| log_format       | object  | 否 | 以 JSON 格式的键值对来声明日志格式。对于值部分，仅支持字符串。如果是以 `$` 开头，则表明是要获取 [APISIX 变量](../apisix-variable.md) 或 [NGINX 内置变量](http://nginx.org/en/docs/varindex.html)。 |
| include_req_body   | boolean | 否 | 当设置为 `true` 时，日志中将包含请求体。如果请求体太大而无法在内存中保存，则由于 Nginx 的限制，无法记录请求体。                                                                                |
| include_req_body_expr | array   | 否 | 当 `include_req_body` 属性设置为 `true` 时的过滤器。只有当此处设置的表达式求值为 `true` 时，才会记录请求体。有关更多信息，请参阅 [lua-resty-expr](https://github.com/api7/lua-resty-expr) 。  |
| include_resp_body      | boolean | 否 | 默认为 `true` ，生成的文件包含响应体。                                                                                                                     |
| code_name      | string  | 否 | 响应结果业务编码属性名，默认`code`属性。                                                                                                                        |
| code_values      | array   | 否 | 响应结果业务编码属性值数组，默认参数值为`[0,-3,-5,-7,-10]`，如果响应结果中业务编码与`code_values`数组中的任意一个相同，插件会在请求日志中添加一个新的属性，属性名由`tag_name`定义，属性值由`match_tag`配置参数定义。           |
| tag_name      | string  | 否 | 业务编码解析结果标签属性名，默认为`code_tag`。                                                                                                                   |
| match_tag      | integer | 否 | 业务编码匹配结果值，默认为1。                                                                                                                                |
| not_match_tag      | integer  | 否 | 业务编码**不匹配**结果值，默认为0。                                                                                                                           |

### 默认日志格式示例

  ```json
  {
    "service_id": "",
    "code_resp_json": 1,
    "code_tag": 1,
    "apisix_latency": 100.99999809265,
    "start_time": 1703907485819,
    "latency": 101.99999809265,
    "upstream_latency": 1,
    "client_ip": "127.0.0.1",
    "route_id": "1",
    "server": {
        "version": "3.7.0",
        "hostname": "localhost"
    },
    "request": {
        "headers": {
            "host": "127.0.0.1:1984",
            "content-type": "application/x-www-form-urlencoded",
            "user-agent": "lua-resty-http/0.16.1 (Lua) ngx_lua/10025",
            "content-length": "12"
        },
        "method": "POST",
        "size": 194,
        "url": "http://127.0.0.1:1984/hello?log_body=no",
        "uri": "/hello?log_body=no",
        "querystring": {
            "log_body": "no"
        }
    },
    "response": {
        "headers": {
            "content-type": "text/plain",
            "connection": "close",
            "content-length": "12",
            "server": "APISIX/3.7.0"
        },
        "status": 200,
        "size": 123
    },
    "upstream": "127.0.0.1:1982"
 }
  ```

## 插件元数据设置

| 名称             | 类型    | 必选项 | 默认值        | 有效值  | 描述                                             |
| ---------------- | ------- | ------ | ------------- | ------- | ------------------------------------------------ |
| log_format       | object  | 可选   |  |         | 以 JSON 格式的键值对来声明日志格式。对于值部分，仅支持字符串。如果是以 `$` 开头，则表明是要获取 [APISIX 变量](../../../en/latest/apisix-variable.md) 或 [NGINX 内置变量](http://nginx.org/en/docs/varindex.html)。 |

:::note 注意

该设置全局生效。如果指定了 `log_format`，则所有绑定 `code-tagger-logger` 的路由或服务都将使用该日志格式。

:::

以下示例展示了如何通过 Admin API 配置插件元数据：

:::note

您可以这样从 `config.yaml` 中获取 `admin_key` 并存入环境变量：

```bash
admin_key=$(yq '.deployment.admin.admin_key[0].key' conf/config.yaml | sed 's/"//g')
```

:::

```shell
curl http://127.0.0.1:9180/apisix/admin/plugin_metadata/code-tagger-logger \
-H "X-API-KEY: $admin_key" -X PUT -d '
{
    "log_format": {
        "host": "$host",
        "@timestamp": "$time_iso8601",
        "client_ip": "$remote_addr"
    }
}'
```

配置完成后，你可以在日志系统中看到如下类似日志：

```shell
{"host":"localhost","@timestamp":"2020-09-23T19:05:05-04:00","client_ip":"127.0.0.1","route_id":"1"}
{"host":"localhost","@timestamp":"2020-09-23T19:05:05-04:00","client_ip":"127.0.0.1","route_id":"1"}
```

## 启用插件

你可以通过以下命令在指定路由中启用该插件：

```shell
curl http://127.0.0.1:9180/apisix/admin/routes/1 \
-H "X-API-KEY: $admin_key" -X PUT -d '
{
  "plugins": {
    "code-tagger-logger": {
      "path": "logs/code_tagger.log"
    }
  },
  "upstream": {
    "type": "roundrobin",
    "nodes": {
      "127.0.0.1:9001": 1
    }
  },
  "uri": "/hello"
}'
```
