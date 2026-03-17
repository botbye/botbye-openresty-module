local constants = {
  pathEvaluate = "/api/v1/protect/evaluate",
  module_version = "1.0.1",
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

local function makeErrorResponse(err_message)
  ngx.log(ngx.ERR, err_message)

  return {
    request_id = "00000000-0000-0000-0000-000000000000",
    decision = "ALLOW",
    risk_score = 0.0,
    signals = empty_table,
    scores = empty_table,
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

function M.evaluate(token, custom_fields)
  local body = cjson.encode({
    server_key = conf.botbye_server_key,
    request = {
      ip = ngx.var.remote_addr,
      token = token or "token missing",
      headers = flattenHeaders(ngx.req.get_headers()),
      request_method = ngx.var.request_method,
      request_uri = ngx.var.request_uri,
    },
    integration = {
      module_name = constants.module_name,
      module_version = constants.module_version,
    },
    custom_fields = custom_fields,
  })

  reusable_params.body = body
  reusable_params.headers = evaluate_headers

  local url = evaluate_base_url .. encode_uri(token or "")
  local res, err = botbye_http.request_uri(url, reusable_params, conf.botbye_connection_timeout)

  if not res or res.status >= 404 then
    if err == "timeout" then
      return makeErrorResponse("[BotBye] API connection timed out, request skipped")
    end

    return makeErrorResponse(
      "[BotBye] Request failed while connecting to the API: " .. (err or tostring(res and res.status or "-")) .. ". Request skipped."
    )
  end

  local raw_body = res.body
  res, err = cjson_safe.decode(raw_body)
  if not res then
    return makeErrorResponse(
      "[BotBye] Failed to decode API response: " .. (err or "unknown") .. ". Request skipped."
    )
  end

  return res, nil, raw_body
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