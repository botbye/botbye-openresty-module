local constants = {
  pathEvaluate = "/api/v1/protect/evaluate",
  module_version = "1.0.4",
  module_name = "OpenResty",
}

local conf = {
  botbye_server_key = "",
  botbye_endpoint = "https://verify.botbye.com",
  botbye_connection_timeout = 1000,
}

local cjson_safe = require("cjson.safe")
local cjson = require("cjson")
local botbye_http = require("botbye_http")

local M = {}

local evaluate_headers  -- initialized in setConf
local evaluate_base_url -- initialized in setConf

local empty_table = {}
local bypass_validation_config = {
  bypass_bot_validation = true,
}

local BOTBYE_RESULT_HEADER = "X-Botbye-Result"
local bypass_result_base64 = ngx.encode_base64(
  cjson.encode({ config = bypass_validation_config })
)

local function makeErrorResponse(err_message)
  ngx.log(ngx.ERR, err_message)

  return {
    request_id = "00000000-0000-0000-0000-000000000000",
    decision = "ALLOW",
    risk_score = 0.0,
    signals = empty_table,
    scores = empty_table,
    config = bypass_validation_config,
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

local reusable_params = {
  method = "POST",
  keep_alive = true,
  body = nil,     -- set per request
  headers = nil,  -- set in setConf
}

local integration_info = {
  module_name = constants.module_name,
  module_version = constants.module_version,
}

local function doEvaluate(payload, token)
  payload.server_key = conf.botbye_server_key
  payload.integration = integration_info

  local ok, encoded_body = pcall(cjson.encode, payload)
  if not ok then
    return makeErrorResponse("[BotBye] Failed to encode request payload: " .. tostring(encoded_body) .. ". Request skipped.")
  end

  reusable_params.body = encoded_body
  reusable_params.headers = evaluate_headers

  local url = evaluate_base_url .. encode_uri(token or "")
  local res, err
  ok, res, err = pcall(botbye_http.request_uri, url, reusable_params, conf.botbye_connection_timeout)
  if not ok then
    return makeErrorResponse("[BotBye] Request failed while connecting to the API: " .. tostring(res) .. ". Request skipped.")
  end

  if not res or res.status == nil or res.status < 200 or res.status >= 300 then
    if err == "timeout" then
      return makeErrorResponse("[BotBye] API connection timed out, request skipped")
    end

    return makeErrorResponse(
      "[BotBye] Request failed while connecting to the API: " .. (err or tostring(res and res.status or "-")) .. ". Request skipped."
    )
  end

  local raw_body = res.body -- json строка
  res, err = cjson_safe.decode(raw_body) -- объект
  if not res then
    return makeErrorResponse(
      "[BotBye] Failed to decode API response: " .. (err or "unknown") .. ". Request skipped."
    )
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
  else
    payload.config = bypass_validation_config
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
      ["Module-Name"] = constants.module_name,
      ["Module-Version"] = constants.module_version,
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

function M.encodeResult(evaluateRes)
  local json = cjson_safe.encode(evaluateRes)
  if json then
    return ngx.encode_base64(json)
  end
  return nil
end

--- Sets X-Botbye-Result header on the current request with the encoded
--- Level 1 evaluate result for propagation to Level 2.
--- Prefers rawBody (avoids re-serialization); falls back to encodeResult;
--- uses bypass default as last resort.
---@param evaluateRes table  evaluate response table
---@param rawBody string|nil  raw JSON body from doEvaluate (3rd return)
function M.propagateResult(evaluateRes, rawBody)
  local encoded = rawBody and ngx.encode_base64(rawBody) or M.encodeResult(evaluateRes)
  ngx.req.set_header(BOTBYE_RESULT_HEADER, encoded or bypass_result_base64)
end

--- Sets X-Botbye-Result header to bypass value (bot validation skipped).
--- Use when request should not be validated (excluded URI, service token, etc).
function M.propagateBypass()
  ngx.req.set_header(BOTBYE_RESULT_HEADER, bypass_result_base64)
end

local function rebuildDerivedState()
  evaluate_base_url = conf.botbye_endpoint .. constants.pathEvaluate .. "?"
  evaluate_headers = {
    Connection = "keep-alive",
    ["Content-Type"] = "application/json",
    ["Module-Name"] = constants.module_name,
    ["Module-Version"] = constants.module_version,
  }
end

function M.setConf(input_conf)
  for k, v in pairs(input_conf) do
    if v == nil or (type(v) == "string" and v:match("^%s*$")) then
      error(k .. " can't be nil or blank.")
    end

    conf[k] = v
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