local constants = {
  path = "/validate-request/v1",
  module_version = "0.0.1",
  module_name = "OpenResty",
}

local conf = {
  botbye_server_key = "",
  botbye_endpoint = "",
  botbye_connection_timeout = 5000,
}

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
    server_name = ngx.var.server_name,
    request_method = ngx.var.request_method,
    request_uri = ngx.var.request_uri,
    created_at = ngx.now(),
    server_port = ngx.var.server_port,
    cookie = ngx.var.http_cookie,
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

local function callBotbye(body, headers)
  local params = {
    method = "POST",
    keep_alive = true,
    body = body,
    headers = headers
  }

  local httpc = require("resty.http").new()
  httpc:set_timeout(conf.botbye_connection_timeout)

  local res, err = httpc:request_uri(conf.botbye_endpoint .. constants.path, params)

  if err ~= nil then
    if err == "timeout" then
      ngx.log(ngx.ERR, "[BotBye] API connection timed out, request skipped")
    else
      ngx.log(ngx.ERR, "[BotBye] Request failed while connecting to the API: ", err, ".")
    end
    return {
      result = { isBot = false, banRequired = false },
      reqId = ngx.var.reqId,
      error = ngx.null
    }
  end

  return require("cjson").decode(res.body)
end

function M.validateRequest(token, custom_fields)
  local body = getBody(token, custom_fields)

  local botbye_headers = {
    Connection = "keep-alive",
    ["Content-Type"] = "application/json",
    ["Module-Name"] = constants.module_name,
    ["Module-Version"] = constants.module_version,
  }

  return callBotbye(body, botbye_headers)
end

function M.setConf(input_conf)
  for k, v in pairs(input_conf) do
    conf[k] = v
  end
end

return M
