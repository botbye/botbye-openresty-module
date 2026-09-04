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

-- Separate from isBlank because isBlank(false) is false, so `origin = false` would read as a real value.
local function isUsableString(value)
  return type(value) == "string" and value:match("^%s*$") == nil
end

local function trim(value)
  return value:match("^%s*(.-)%s*$")
end

-- Unusable when absent, blank, the literal "null", or carrying a control char — it goes into the header
-- verbatim, so a CR/LF in a Referer would inject one.
local function isMissingHeaderValue(value)
  if not isUsableString(value) then
    return true
  end

  local trimmed = trim(value)

  return trimmed:lower() == "null" or trimmed:find("[%z\1-\8\10-\31\127]") ~= nil
end

local image_base_url
local init_request_url

local function rebuildDerivedState()
  local base = (conf.endpoint or ""):gsub("/+$", "")
  -- /server route: the backend reads the module from the headers, which browser tags cannot set.
  image_base_url = base .. "/api/v1/phishing/image/" .. conf.client_key .. "/server"
  init_request_url = base .. "/api/v1/phishing/init-request/v1/" .. conf.client_key
end

function M.setConf(input_conf)
  for k, v in pairs(input_conf) do
    if conf[k] == nil then
      -- Unknown key: log, don't crash worker init.
      ngx.log(ngx.ERR, "[BotBye] ignoring unknown config key: ", tostring(k))
    elseif isBlank(v) then
      -- Blank value: log and keep the current one.
      ngx.log(ngx.ERR, "[BotBye] ignoring blank config value for key: ", tostring(k))
    else
      conf[k] = v
    end
  end

  rebuildDerivedState()
end

-- get_uri_args() returns a table for a repeated param and true for a valueless one (`?flag`);
-- tostring() on either used to leak `table: 0x7f…` upstream.
local function appendParam(parts, key, value)
  if value == true then
    parts[#parts + 1] = key -- valueless param: emit the bare key, the way it arrived
  elseif value ~= false then
    parts[#parts + 1] = key .. "=" .. ngx.escape_uri(tostring(value))
  end
end

-- Fixed order: the key set is closed by forwardable() plus the params fetchCatcher sets, so the URL is
-- deterministic by construction, and the keys are literals with nothing to escape.
local URL_PARAMS = { "executable", "format", "image_id", "module_name", "module_version" }

local function buildUrl(query)
  local parts = {}
  for _, key in ipairs(URL_PARAMS) do
    local v = query[key]
    if type(v) == "table" then
      -- Repeated param: array order is the order it arrived in, so keep it.
      for _, item in ipairs(v) do
        appendParam(parts, key, item)
      end
    elseif v ~= nil then
      -- Load-bearing nil check: appendParam takes its `value ~= false` branch for nil, which would put
      -- `executable=nil` on the wire.
      appendParam(parts, key, v)
    end
  end

  -- Unreachable while `format` is always set, but a bare trailing "?" would be worse.
  if #parts == 0 then
    return image_base_url
  end

  return image_base_url .. "?" .. table.concat(parts, "&")
end

local function errorStatus(failure)
  return failure == "timeout" and 504 or 502
end

local function fetchAsset(origin, referer, query)
  local params = {
    method = "GET",
    keepalive = true,
    headers = {
      ["Module-Name"] = module_info.name,
      ["Module-Version"] = module_info.version,
    },
  }

  -- Only forward a header when there is a real value
  if not isMissingHeaderValue(origin) then
    params.headers["Origin"] = trim(origin)
  end

  if not isMissingHeaderValue(referer) then
    params.headers["Referer"] = trim(referer)
  end

  -- pcall: request_uri() can throw on a bad URL/host; never a 500 on the pixel path.
  local ok, res, err = pcall(botbye_http.request_uri, buildUrl(query), params, conf.connection_timeout)
  if not ok then
    local failure = botbye_http.classifyError(tostring(res))
    return nil, failure, errorStatus(failure)
  end
  if not res then
    -- nil fallback: an unrecognised transport error passes through.
    local failure = botbye_http.classifyError(err)
    return nil, failure, errorStatus(failure)
  end
  return res, err
end

-- Read off the request — `ngx.var` IS the request — so a handler passes neither; `opts` can override.
-- Referer matters: an `<object data="…svg">` pixel has no Origin.
--
-- `ngx.var` is only readable in a request phase (rewrite/access/content). Calling fetchCatcher from
-- init_worker_by_lua or a timer throws "API disabled in the current context"; pass `origin`/`referer`
-- explicitly there.
local function requestOrigin(opts)
  if opts.origin ~= nil then
    return opts.origin
  end
  return ngx.var.http_origin
end

local function requestReferer(opts)
  if opts.referer ~= nil then
    return opts.referer
  end
  return ngx.var.http_referer
end

-- Attribution params only, read by name rather than walked: get_uri_args() yields up to max_args, 100
-- by default. A non-table query counts as empty rather than erroring outside the pcall.
local function forwardable(query)
  if type(query) ~= "table" then
    return {}
  end

  return { module_name = query.module_name, module_version = query.module_version }
end

-- Fetch the catcher asset. Returns `res, err` — plus, when `res` is nil, the gateway status the failure
-- means as a third value: 504 for a timeout, 502 for anything else. `opts`:
--
--   format  (string, required) "png" — the 1×1 pixel — or "svg" — the wrapper that fetches it. Anything
--           else returns `nil, "invalid format"`; never defaulted, since a wrong guess is a silently
--           mis-attributed pixel.
--   origin, referer (string) override the headers read off the current request.
--
-- The attribution params are read off the current request's query string.
--
-- SVG only, ignored for "png":
--
--   inner_png_url  (string, required for "svg") sent as `image_id`. An absolute http(s) URL of your own
--                  PNG location, so the nested fetch proxies through your origin too. Missing or blank
--                  returns `nil, "missing inner_png_url"`.
--   skip_execution (boolean) ask for the script-less SVG (`executable=false`). Defaults to true, always
--                  sent.
function M.fetchCatcher(opts)
  opts = opts or {}

  -- Logged and returned, not raised: this serves a location the browser is fetching an image from, and
  -- the pcall around request_uri exists precisely so that path never turns into a 500. An ERR line is
  -- what surfaces the misconfiguration at integration time.
  if opts.format ~= "png" and opts.format ~= "svg" then
    ngx.log(ngx.ERR, '[BotBye] fetchCatcher: opts.format must be "png" or "svg", got ', tostring(opts.format))
    return nil, "invalid format", 502
  end

  local ok, args = pcall(ngx.req.get_uri_args)
  local query = forwardable(ok and args)
  query.format = opts.format

  if opts.format == "svg" then
    if not isUsableString(opts.inner_png_url) then
      ngx.log(ngx.ERR, '[BotBye] fetchCatcher: opts.inner_png_url is required for format="svg", got ',
        tostring(opts.inner_png_url))
      return nil, "missing inner_png_url", 502
    end

    query.image_id = trim(opts.inner_png_url)

    -- Only an explicit false opts into the script-carrying SVG.
    query.executable = opts.skip_execution == false and "true" or "false"
  end

  return fetchAsset(requestOrigin(opts), requestReferer(opts), query)
end

-- Reports the server-side phishing integration to the backend. Best-effort: never blocks the worker.
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

-- Once per nginx instance; call from `init_worker_by_lua`. Guarded to worker 0 plus a `botbye_state`
-- flag so workers don't each POST, then dispatched via a 0-delay timer.
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
