local conf = {
  endpoint = "https://verify.botbye.com",
  account_id = "",
  project_id = "",
  api_key = "",
  connection_timeout = 1000,
}

local M = {}
local botbye_http = require("botbye_http")

local function assertNotBlank(key, value)
  if value == nil or (type(value) == "string" and value:match("^%s*$")) then
    error(key .. " can't be nil or blank.")
  end
end

local image_base_url

local function rebuildDerivedState()
  local base = (conf.endpoint or ""):gsub("/+$", "")
  image_base_url = base .. "/api/v1/phishing/" .. conf.account_id
    .. "/projects/" .. conf.project_id .. "/image"
end

local reusable_params = {
  method = "GET",
  keep_alive = true,
  headers = {
    ["X-Api-Key"] = "",
    ["Origin"] = nil,
  },
}

function M.setConf(input_conf)
  for k, v in pairs(input_conf) do
    assertNotBlank(k, v)
    conf[k] = v
  end

  rebuildDerivedState()
  reusable_params.headers["X-Api-Key"] = conf.api_key
end

function M.fetchImage(origin, image_id)
  local url
  if image_id then
    url = image_base_url .. "?image_id=" .. ngx.escape_uri(image_id) .. "&format=svg"
  else
    url = image_base_url .. "?format=png"
  end

  reusable_params.headers["Origin"] = origin or "origin is missing"

  return botbye_http.request_uri(url, reusable_params, conf.connection_timeout)
end

return M
