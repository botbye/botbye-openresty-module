local constants = {
  pathV2 = "/validate-request/v2",
  module_version = "0.0.14",
  module_name = "OpenResty",
}

local conf = {
  botbye_server_key = "",
  botbye_endpoint = "https://verify.botbye.com",
  botbye_connection_timeout = 1000,
}

local cjson_safe = require("cjson.safe")
local cjson = require("cjson")

local M = {}

local function getHeaders(headers)
  for key, value in pairs(headers) do
    if type(value) == "table" then
      headers[key] = table.concat(value, ", ")
    end
  end

  return headers
end

local function getBody(token, custom_fields)
  local request_infos = {
    remote_addr = ngx.var.remote_addr,
    request_method = ngx.var.request_method,
    request_uri = ngx.var.request_uri,
  }

  local visitor = {
    token = token or 'token missing',
    server_key = conf["botbye_server_key"],
    headers = getHeaders(ngx.req.get_headers()),
    request_info = request_infos,
    custom_fields = custom_fields
  }

  return cjson.encode(visitor)
end

local function encode_uri_char(char)
  return string.format('%%%0X', string.byte(char))
end

local function encode_uri(uri)
  return (string.gsub(uri, "[^%a%d%-_%.!~%*'%(%);/%?:@&=%+%$,#]", encode_uri_char))
end

local function callBotbyeV2(token, params)
  local httpc = require("resty.http").new()
  httpc:set_timeout(conf.botbye_connection_timeout)

  local res, err = httpc:request_uri(conf.botbye_endpoint .. constants.pathV2 .. "?" .. encode_uri(token), params)

  httpc:set_keepalive()

  return res, err
end

function M.validateRequest(token, custom_fields)
  local body = getBody(token, custom_fields)

  local botbye_headers = {
    Connection = "keep-alive",
    ["Content-Type"] = "application/json",
    ["Module-Name"] = constants.module_name,
    ["Module-Version"] = constants.module_version,
  }

  local params = {
    method = "POST",
    keep_alive = true,
    body = body,
    headers = botbye_headers
  }

  local res, err = callBotbyeV2(token, params)

  if not res or res.status >= 404 then
    local err_message

    if err == "timeout" then
      err_message = "[BotBye] API connection timed out, request skipped"
      ngx.log(ngx.ERR, err_message)
    else
      err_message = "[BotBye] Request failed while connecting to the API: " .. (err or res.status or "-") .. ". Request skipped."
      ngx.log(ngx.ERR, err_message)
    end

    return {
      result = { isAllowed = true },
      reqId = ngx.var.reqId or '00000000-0000-0000-0000-000000000000',
      error = { message = err_message }
    }
  end

  res, err = cjson_safe.decode(res.body)
  if not res then
    local err_message = "[BotBye] Request failed while connecting to the API, response: " .. err .. ".Request skipped."
    ngx.log(ngx.ERR, err_message)

    return {
      result = { isAllowed = true },
      reqId = ngx.var.reqId or '00000000-0000-0000-0000-000000000000',
      error = { message = err_message }
    }
  end

  return res
end

local function initRequest()
  ngx.log(ngx.INFO, "[BotBye] init-request: starting")

  local httpc = require("resty.http").new()
  httpc:set_timeout(conf.botbye_connection_timeout)

  local url = conf.botbye_endpoint:gsub("/+$", "") .. "/init-request/v1"
  local body = cjson.encode({ serverKey = conf.botbye_server_key })
  ngx.log(ngx.INFO, "[BotBye] init-request: url = " .. url)
  ngx.log(ngx.INFO, "[BotBye] init-request: body = " .. body)

  local res, err = httpc:request_uri(url, {
    method = "POST",
    body = body,
    headers = {
      ["Content-Type"] = "application/json",
      ["Module-Name"] = constants.module_name,
      ["Module-Version"] = constants.module_version,
      ["X-Botbye-Server-Key"] = conf.botbye_server_key,
    },
  })

  httpc:set_keepalive()

  if not res then
    ngx.log(ngx.WARN, "[BotBye] init-request failed: " .. (err or "unknown error"))
    return
  end

  ngx.log(ngx.INFO, "[BotBye] init-request: HTTP status = " .. tostring(res.status))
  ngx.log(ngx.INFO, "[BotBye] init-request: raw response = " .. tostring(res.body))

  local decoded, decode_err = cjson_safe.decode(res.body)
  if not decoded then
    ngx.log(ngx.WARN, "[BotBye] init-request decode error: " .. (decode_err or "unknown"))
    return
  end

  if decoded.error ~= nil or decoded.status ~= "ok" then
    ngx.log(ngx.WARN, "[BotBye] init-request error = " .. tostring(decoded.error) .. "; status = " .. tostring(decoded.status))
  else
    ngx.log(ngx.INFO, "[BotBye] init-request: success, status = " .. tostring(decoded.status))
  end
end

function M.setConf(input_conf)
  for k, v in pairs(input_conf) do
    if v == nil or (type(v) == "string" and v:match("^%s*$")) then
      error(k..' can\'t be nil or blank.')
    end

    conf[k] = v
  end
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