local conf = {
  endpoint = "https://verify.botbye.com",
  client_key = "",
  connection_timeout = 1000,
}

local M = {}
local botbye_http = require("botbye_http")
local module_info = require("botbye_module_info")

local function isBlank(value)
  return value == nil or (type(value) == "string" and value:match("^%s*$"))
end

local image_base_url
local init_request_url

local function rebuildDerivedState()
  local base = (conf.endpoint or ""):gsub("/+$", "")
  -- The pixel is proxied server-side, so it hits the /server route: the backend reads the module from
  -- the Module-Name/Module-Version headers (browser tags can't set headers) and marks SERVER_IMAGE_FETCHED.
  image_base_url = base .. "/api/v1/phishing/image/" .. conf.client_key .. "/server"
  init_request_url = base .. "/api/v1/phishing/init-request/v1/" .. conf.client_key
end

function M.setConf(input_conf)
  for k, v in pairs(input_conf) do
    if conf[k] == nil then
      -- Unknown key: log but don't crash worker init (fail-open, forward-compatible).
      ngx.log(ngx.ERR, "[BotBye] ignoring unknown config key: ", tostring(k))
    elseif isBlank(v) then
      -- Blank value: log and keep the existing/default value — never crash worker init.
      ngx.log(ngx.ERR, "[BotBye] ignoring blank config value for key: ", tostring(k))
    else
      conf[k] = v
    end
  end

  rebuildDerivedState()
end

-- `query` (table|nil) is forwarded verbatim to the /server route — pass the browser's original
-- pixel query (format, image_id, and the JS tag's module_name / module_version).
function M.fetchImage(origin, query)
  local url = image_base_url
  if query then
    local parts = {}
    for k, v in pairs(query) do
      parts[#parts + 1] = ngx.escape_uri(tostring(k)) .. "=" .. ngx.escape_uri(tostring(v))
    end
    if #parts > 0 then
      url = image_base_url .. "?" .. table.concat(parts, "&")
    end
  end

  local params = {
    method = "GET",
    keepalive = true,
    headers = {
      ["Origin"] = origin or "origin is missing",
      ["Module-Name"] = module_info.name,
      ["Module-Version"] = module_info.version,
    },
  }

  -- pcall: request_uri() can throw (bad URL/host); never let it surface as a 500 on the
  -- pixel-serving path. Mirrors the protect flow in botbye.lua.
  local ok, res, err = pcall(botbye_http.request_uri, url, params, conf.connection_timeout)
  if not ok then
    return nil, botbye_http.classifyError(tostring(res))
  end
  if not res then
    -- nil fallback: an unrecognised transport error passes through verbatim.
    return nil, botbye_http.classifyError(err)
  end
  return res, err
end

-- Reports the server-side phishing integration to the backend (the SERVER_INTEGRATION_INIT
-- get-started milestone). Best-effort: failures are logged and swallowed, never blocking the worker.
local function sendPhishingInit()
  local res, err = botbye_http.request_uri(init_request_url, {
    method = "POST",
    headers = {
      ["Module-Name"] = module_info.name,
      ["Module-Version"] = module_info.version,
    },
  }, conf.connection_timeout)

  if not res then
    ngx.log(ngx.WARN, "[BotBye] phishing init-request failed: ", err or "unknown error")
    return
  end

  if res.status and (res.status < 200 or res.status >= 300) then
    ngx.log(ngx.WARN, "[BotBye] phishing init-request: HTTP status = ", res.status)
  else
    ngx.log(ngx.INFO, "[BotBye] phishing init-request: success")
  end
end

-- Fires the init handshake once per nginx instance. Call from `init_worker_by_lua`, mirroring
-- `botbye.initRequest()`: guarded to worker 0 + a `botbye_state` shared-dict flag so concurrent
-- workers don't each POST, then dispatched off the worker-init phase via a 0-delay timer.
function M.initRequest()
  if ngx.worker.id() == 0 then
    local dict = ngx.shared and ngx.shared.botbye_state
    if not dict then
      ngx.log(ngx.WARN, "[BotBye] shared dict 'botbye_state' not configured, skipping phishing init guard")
      return
    end

    local ok, err = dict:add("botbye:phishing_init_done", true)
    if ok ~= true then
      if ok == nil and err ~= nil then
        ngx.log(ngx.WARN, "[BotBye] phishing init-request shared dict error: " .. tostring(err))
      end
      return
    end

    ngx.timer.at(0, function(premature)
      if premature then return end
      sendPhishingInit()
    end)
  end
end

-- Ensure derived URLs are initialised even if setConf is never called.
rebuildDerivedState()

return M
