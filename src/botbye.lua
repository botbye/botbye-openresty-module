local constants = {
  pathV2 = "/validate-request/v2",
  module_version = "0.0.6",
  module_name = "OpenResty",
}

local conf = {
  botbye_server_key = "",
  botbye_endpoint = "",
  botbye_connection_timeout = 1000,
}

local M = {}

local function safe_decode(json_string)
  local success, decoded_json = pcall(require("cjson").decode, json_string)
  if success then
    return decoded_json
  else
    local err_message = "[BotBye] Request failed while connecting to the API, response: " .. (json_string or "-") .. ".Request skipped."
    ngx.log(ngx.ERR, err_message)

    return {
      result = { isAllowed = true },
      reqId = ngx.var.reqId or '00000000-0000-0000-0000-000000000000',
      error = { message = err_message }
    }
  end
end

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
    server_name = ngx.var.server_name,
    request_method = ngx.var.request_method,
    request_uri = ngx.var.request_uri,
    created_at = ngx.now(),
    server_port = ngx.var.server_port,
  }

  local visitor = {
    token = token,
    server_key = conf["botbye_server_key"],
    headers = getHeaders(ngx.req.get_headers()),
    request_info = request_infos,
    custom_fields = custom_fields
  }

  return require("cjson").encode(visitor)
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

  return httpc:request_uri(conf.botbye_endpoint .. constants.pathV2 .. "?" .. encode_uri(token), params)
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

  if res.status >= 404 then
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

  return safe_decode(res.body)
end

function M.setConf(input_conf)
  for k, v in pairs(input_conf) do
    conf[k] = v
  end
end

return M
