local constants = {
  pathEvaluate = "/api/v1/protect/evaluate",
}

local conf = {
  botbye_server_key = "",
  botbye_endpoint = "https://verify.botbye.com",
  botbye_connection_timeout = 1000,
}

local cjson_safe = require("cjson.safe")
local cjson = require("cjson")
local botbye_http = require("botbye_http")
local module_info = require("botbye_module_info")

local M = {}

local evaluate_headers  -- initialized in setConf
local evaluate_base_url -- initialized in setConf

local function makeErrorResponse(err_message)
  ngx.log(ngx.ERR, err_message)

  return {
    decision = "ALLOW",
    error = { message = err_message },
  }
end

local function flattenHeaders(headers)
  for key, value in pairs(headers) do
    if type(value) == "table" then
      headers[key] = table.concat(value, ", ")
    end
  end

  return headers
end

local uri_encode_lut = {}
for i = 0, 255 do
  uri_encode_lut[string.char(i)] = string.format("%%%02X", i)
end

local function encode_uri(uri)
  return (string.gsub(uri, "[^%a%d%-_%.!~%*'%(%);/%?:@&=%+%$,#]", uri_encode_lut))
end

local integration_info = {
  module_name = module_info.name,
  module_version = module_info.version,
}

local function doEvaluate(payload, token)
  payload.server_key = conf.botbye_server_key
  payload.integration = integration_info

  local ok, encoded_body = pcall(cjson.encode, payload)
  if not ok then
    return makeErrorResponse("[BotBye] Failed to encode request payload: " .. tostring(encoded_body) .. ". Request skipped.")
  end

  -- Build a fresh params table per request. A module-level reusable table is unsafe here:
  -- request_uri() yields on connect/send, so a concurrent request running in another
  -- coroutine could overwrite `body` between assignment and the actual send — leaking one
  -- request's payload under another request.
  local params = {
    method = "POST",
    keepalive = true,
    body = encoded_body,
    headers = evaluate_headers,
  }

  local url = evaluate_base_url .. encode_uri(token or "")
  local res, err
  ok, res, err = pcall(botbye_http.request_uri, url, params, conf.botbye_connection_timeout)
  if not ok then
    ngx.log(ngx.WARN, "[BotBye] request pcall error: ", tostring(res))
    return makeErrorResponse("connection error")
  end

  if not res or res.status == nil or res.status < 200 or res.status >= 300 then
    ngx.log(ngx.WARN, "[BotBye] request error: ", (err or tostring(res and res.status or "-")))
    -- "connection error" fallback: a non-2xx status (err == nil) or any
    -- unrecognised transport error maps to the catch-all, never a raw lib string.
    return makeErrorResponse(botbye_http.classifyError(err, "connection error"))
  end

  local raw_body = res.body -- json строка
  res, err = cjson_safe.decode(raw_body) -- объект
  if not res then
    ngx.log(ngx.WARN, "[BotBye] JSON decode error: ", (err or "unknown"))
    return makeErrorResponse("invalid json response")
  end

  -- Preserve empty arrays (cjson decodes [] as {} which re-encodes as object)
  if res.signals and type(res.signals) == "table" and next(res.signals) == nil then
    setmetatable(res.signals, cjson.array_mt)
  end

  return res, nil, raw_body
end

--- Level 1: Bot validation (proxy, pre-authentication).
--- Validates device token and returns bot score.
--- No user context — only bot detection.
---@param token string
---@param custom_fields table|nil
function M.botValidation(token, custom_fields)
  return doEvaluate({
    type = "validate",
    request = {
      ip = ngx.var.remote_addr,
      token = token or "token missing",
      headers = flattenHeaders(ngx.req.get_headers()),
      request_method = ngx.var.request_method,
      request_uri = ngx.var.request_uri,
    },
    custom_fields = custom_fields,
  }, token)
end

--- Level 2: Risk evaluation (middleware, post-authentication).
--- Evaluates ATO/abuse risk using user context and dynamic metrics.
--- Bot score comes from Level 1 result (botbye_result).
---@param opts table { user: { account_id, username?, email?, phone? }, event_type: string, event_status: string ("SUCCESSFUL"|"FAILED"|"ATTEMPTED"), botbye_result?: string, custom_fields?: table, config?: table }
function M.riskEvaluation(opts)
  local payload = {
    type = "risk",
    event = {
      type = opts.event_type,
      status = opts.event_status,
    },
    user = opts.user,
    request = {
      ip = ngx.var.remote_addr,
      headers = flattenHeaders(ngx.req.get_headers()),
    },
    custom_fields = opts.custom_fields,
  }

  if opts.botbye_result ~= nil and (type(opts.botbye_result) ~= "string" or not opts.botbye_result:match("^%s*$")) then
    payload.botbye_result = opts.botbye_result
  end

  return doEvaluate(payload, nil)
end

--- Combined Level 1+2: Bot validation + risk evaluation in a single call.
--- Use when there is no separate proxy — the middleware validates the token
--- and evaluates ATO/abuse risk in one request.
---@param opts table { token: string, user: { account_id, username?, email?, phone? }, event_type: string, event_status: string ("SUCCESSFUL"|"FAILED"|"ATTEMPTED"), custom_fields?: table }
function M.fullEvaluation(opts)
  local token = opts.token
  return doEvaluate({
    type = "full",
    event = {
      type = opts.event_type,
      status = opts.event_status,
    },
    user = opts.user,
    request = {
      ip = ngx.var.remote_addr,
      token = token or "token missing",
      headers = flattenHeaders(ngx.req.get_headers()),
      request_method = ngx.var.request_method,
      request_uri = ngx.var.request_uri,
    },
    custom_fields = opts.custom_fields,
  }, token)
end

local function initRequest()
  ngx.log(ngx.INFO, "[BotBye] init-request: starting")

  local url = conf.botbye_endpoint:gsub("/+$", "") .. "/init-request/v1"
  local body = cjson.encode({ serverKey = conf.botbye_server_key })
  ngx.log(ngx.INFO, "[BotBye] init-request: url = ", url, ", body = ", body)

  local res, err = botbye_http.request_uri(url, {
    method = "POST",
    body = body,
    headers = {
      ["Content-Type"] = "application/json",
      ["Module-Name"] = module_info.name,
      ["Module-Version"] = module_info.version,
    },
  }, conf.botbye_connection_timeout)

  if not res then
    ngx.log(ngx.WARN, "[BotBye] init-request failed: ", err or "unknown error")
    return
  end

  ngx.log(ngx.INFO, "[BotBye] init-request: HTTP status = ", res.status)

  local decoded, decode_err = cjson_safe.decode(res.body)
  if not decoded then
    ngx.log(ngx.WARN, "[BotBye] init-request decode error: ", decode_err or "unknown")
    return
  end

  if decoded.error ~= nil or decoded.status ~= "ok" then
    ngx.log(ngx.WARN, "[BotBye] init-request error = ", tostring(decoded.error), "; status = ", tostring(decoded.status))
  else
    ngx.log(ngx.INFO, "[BotBye] init-request: success, status = ", decoded.status)
  end
end

local function rebuildDerivedState()
  local base = (conf.botbye_endpoint or ""):gsub("/+$", "")
  evaluate_base_url = base .. constants.pathEvaluate .. "?"
  evaluate_headers = {
    Connection = "keep-alive",
    ["Content-Type"] = "application/json",
    ["Module-Name"] = module_info.name,
    ["Module-Version"] = module_info.version,
  }
end

function M.setConf(input_conf)
  for k, v in pairs(input_conf) do
    if conf[k] == nil then
      -- Unknown key: log but don't crash worker init (fail-open, forward-compatible).
      ngx.log(ngx.ERR, "[BotBye] ignoring unknown config key: ", tostring(k))
    elseif v == nil or (type(v) == "string" and v:match("^%s*$")) then
      -- Blank value: log and keep the existing/default value — never crash worker init.
      ngx.log(ngx.ERR, "[BotBye] ignoring blank config value for key: ", tostring(k))
    else
      conf[k] = v
    end
  end

  rebuildDerivedState()
end

function M.initRequest()
  if ngx.worker.id() == 0 then
    local dict = ngx.shared and ngx.shared.botbye_state
    if not dict then
      ngx.log(ngx.WARN, "[BotBye] shared dict 'botbye_state' not configured, skipping init guard")
      return
    end

    local ok, err = dict:add("botbye:init_done", true)
    if ok ~= true then
      if ok == nil and err ~= nil then
        ngx.log(ngx.WARN, "[BotBye] init-request shared dict error: " .. tostring(err))
      end
      return
    end

    ngx.timer.at(0, function(premature)
      if premature then return end
      initRequest()
    end)
  end
end

return M