# BotBye OpenResty Module

Lua module for the [BotBye](https://botbye.com) Unified Protection Platform — unifying fraud prevention and real-time event monitoring in one platform.

BotBye goes beyond fixed bot/ATO checks. Risk dimensions and metrics are fully dynamic — you define what to measure and what rules to apply per project. This means the same platform covers bot detection, account takeover, multi-accounting, payment fraud, promotion abuse, or any custom fraud scenario specific to your business.

## Requirements

- OpenResty (nginx + LuaJIT)
- lua-resty-http 0.17.1

## Installation

### LuaRocks

```bash
luarocks install botbye-openresty
```

### Manual

Copy `src/botbye.lua`, `src/botbye_http.lua`, and `src/botbye_phishing.lua` to your OpenResty Lua modules directory (e.g., `/usr/local/openresty/nginx/lua/`).

## Overview

The module provides three functions for different integration levels:

| Function | Use Case | Where It Runs |
|---|---|---|
| `botbye.botValidation()` | **Level 1** — Bot filtering | Proxy (`access_by_lua`), before user identity is known |
| `botbye.riskEvaluation()` | **Level 2** — Risk scoring & event logging | Application layer, when user identity is known |
| `botbye.fullEvaluation()` | **Level 1+2 combined** | Application layer when no separate proxy exists |

All requests go to a single endpoint (`POST /api/v1/protect/evaluate`) and return a unified response with a decision (`ALLOW`, `CHALLENGE`, `BLOCK`), risk scores per dimension, and triggered signals. Dimensions are dynamic — the platform ships with built-in ones (`bot`, `ato`, `abuse`) but you can define custom dimensions (e.g., `payment_fraud`, `promotion_abuse`) per project without code changes.

Every evaluation call is also recorded as a **protection event** — logged to the analytics pipeline and used to compute real-time metrics that feed the rules engine. Metrics are fully configurable per project: the platform ships with built-in ones (failed logins, distinct IPs per account, device reuse, etc.) and you can define custom metrics for your specific use case (e.g., "failed transactions over $1000 per account in 1 hour"). This means `riskEvaluation()` serves a dual purpose: it both evaluates risk **and** logs the event for future analysis and metric aggregation.

## Quick Start

### 1. Configure nginx

Add a shared dictionary for the init guard and configure the module:

```nginx
http {
    lua_shared_dict botbye_state 1m;

    init_worker_by_lua_block {
        local botbye = require("botbye")
        botbye.setConf({
            botbye_server_key = "your-server-key", -- from https://app.botbye.com
        })
        botbye.initRequest()
    }
}
```

### 2. Bot Validation (Level 1)

Validate device tokens where user identity is not yet available — at the proxy layer before authentication.

```nginx
location / {
    access_by_lua_block {
        local botbye = require("botbye")

        -- extract the token from wherever you pass it: query param, header, body, etc.
        local token = ngx.var.arg_botbye_token or ""
        local response, _, raw_body = botbye.botValidation(token)

        if response.decision == "BLOCK" then
            ngx.exit(ngx.HTTP_FORBIDDEN)
        end

        -- Propagate bot score to Level 2 via header
        botbye.propagateResult(response, raw_body)
    }

    proxy_pass http://backend;
}
```

### 3. Risk Scoring & Event Logging (Level 2)

Evaluate risk and log events when user identity is known. Each call both scores the request **and** feeds the real-time metrics engine, so you should call `riskEvaluation()` for every significant user action — not just when you need a decision.

```lua
local botbye = require("botbye")

local response = botbye.riskEvaluation({
    user = {
        account_id = user_id,
        email = user_email,       -- optional
        phone = user_phone,       -- optional
    },
    event_type = "LOGIN",
    event_status = "SUCCESSFUL",
    botbye_result = ngx.var.http_x_botbye_result, -- from Level 1
})

if response.decision == "BLOCK" then
    ngx.exit(ngx.HTTP_FORBIDDEN)
elseif response.decision == "CHALLENGE" then
    -- show challenge
end
```

When `botbye_result` is `nil` (no Level 1 upstream), bot validation is automatically bypassed.

#### Event Types

`event_type` is an arbitrary string — the server accepts any value. Pass any string that matches your business domain:

```lua
"LOGIN"
"REGISTRATION"
"TRANSACTION"
"BONUS_CLAIM"
"PASSWORD_RESET"
"WITHDRAWAL"
```

#### Using Level 2 for Event Logging

Even when you don't need to act on the decision, sending events builds the metrics profile for the account. This enables rules like "more than 5 failed logins in 10 minutes" or "distinct devices per account in 1 hour":

```lua
-- Log a failed login attempt — feeds metrics even if you don't act on the decision
botbye.riskEvaluation({
    user = { account_id = user_id },
    event_type = "LOGIN",
    event_status = "FAILED",
})

-- Log a custom business event
botbye.riskEvaluation({
    user = { account_id = user_id },
    event_type = "BONUS_CLAIM",
    event_status = "SUCCESSFUL",
    custom_fields = { bonus_id = "welcome_100" },
})
```

### 4. Full Evaluation (Level 1+2 Combined)

Use when there is no separate proxy layer — validates the device token and evaluates risk in a single call.

```lua
local botbye = require("botbye")

local response = botbye.fullEvaluation({
    token = ngx.var.arg_botbye_token or "",
    user = { account_id = user_id },
    event_type = "LOGIN",
    event_status = "FAILED",
})
```

## Response

The response table contains:

| Field | Type | Description |
|---|---|---|
| `request_id` | `string` | Request UUID |
| `decision` | `string` | `"ALLOW"`, `"CHALLENGE"`, or `"BLOCK"` |
| `risk_score` | `number` | Overall risk score (0–1) |
| `scores` | `table` | Per-dimension scores (`bot`, `ato`, `abuse`, ...) |
| `signals` | `table` | Triggered signal names (e.g., `BruteForce`, `ImpossibleTravel`) |
| `challenge` | `table?` | Challenge type and token (when decision is `CHALLENGE`) |
| `extra_data` | `table?` | Enriched device data (IP, country, browser, device, etc.) |
| `config` | `table` | Config flags (`bypass_bot_validation`) |
| `error` | `table?` | Error details (on fallback) |

```lua
response.decision                -- "ALLOW"
response.risk_score              -- 0.72
response.scores                  -- { bot = 0.15, ato = 0.72, abuse = 0.05 }
response.signals                 -- { "BruteForce", "ImpossibleTravel" }
response.challenge.type          -- "captcha"
response.extra_data.country      -- "US"
```

## Level 1 to Level 2 Propagation

When using both levels, propagate the Level 1 result to Level 2 via the `X-Botbye-Result` header. This allows the platform to link both evaluations by `requestId` and combine bot score from Level 1 with risk scores from Level 2 into a single unified result:

```lua
-- Level 1 (proxy) — validate and forward result
local response, _, raw_body = botbye.botValidation(token)
botbye.propagateResult(response, raw_body)

-- Or bypass validation entirely
botbye.propagateBypass()

-- Level 2 (backend) — pass the header value as botbye_result
local response = botbye.riskEvaluation({
    -- ...
    botbye_result = ngx.var.http_x_botbye_result,
})
```

## Configuration

```lua
botbye.setConf({
    botbye_server_key = "your-server-key",         -- from https://app.botbye.com
    botbye_endpoint = "https://verify.botbye.com",  -- default
    botbye_connection_timeout = 1000,               -- timeout in ms, default
})
```

### nginx Configuration

```nginx
http {
    # Required for init guard (prevents duplicate init requests)
    lua_shared_dict botbye_state 1m;

    init_worker_by_lua_block {
        local botbye = require("botbye")
        botbye.setConf({
            botbye_server_key = "your-server-key",
        })
        botbye.initRequest()
    }
}
```

## Error Handling

The module follows a **fail-open** strategy. On network or server errors, evaluation functions return a bypass response (`decision = "ALLOW"` with `bypass_bot_validation = true`) instead of raising errors:

```lua
local response = botbye.riskEvaluation(opts)

if response.error then
    -- Evaluation failed, request was allowed by default
    ngx.log(ngx.WARN, response.error.message)
end
```

## Complete nginx Example

```nginx
http {
    lua_shared_dict botbye_state 1m;
    lua_package_path "/usr/local/openresty/nginx/lua/?.lua;;";

    init_worker_by_lua_block {
        local botbye = require("botbye")
        botbye.setConf({
            botbye_server_key = "your-server-key",
        })
        botbye.initRequest()
    }

    server {
        listen 80;

        # Level 1: Bot validation at the proxy layer
        location / {
            access_by_lua_block {
                local botbye = require("botbye")
                local token = ngx.var.arg_botbye_token or ""

                local response, _, raw_body = botbye.botValidation(token)

                if response.decision == "BLOCK" then
                    ngx.exit(ngx.HTTP_FORBIDDEN)
                end

                botbye.propagateResult(response, raw_body)
            }

            proxy_pass http://backend;
        }
    }
}
```

## Testing

```bash
luarocks make botbye-openresty-*.rockspec
```

## License

MIT

## Support

For support, visit [botbye.com](https://botbye.com) or contact [accounts@botbye.com](mailto:accounts@botbye.com).
