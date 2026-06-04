local conf = {
  endpoint = "https://verify.botbye.com",
  client_key = "",
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
local image_png_url
local image_svg_prefix

local function rebuildDerivedState()
  local base = (conf.endpoint or ""):gsub("/+$", "")
  image_base_url = base .. "/api/v1/phishing/image/" .. conf.client_key
  image_png_url = image_base_url .. "?format=png"
  image_svg_prefix = image_base_url .. "?image_id="
end

function M.setConf(input_conf)
  for k, v in pairs(input_conf) do
    assertNotBlank(k, v)
    conf[k] = v
  end

  rebuildDerivedState()
end

function M.fetchImage(origin, image_id)
  local url
  if image_id then
    url = image_svg_prefix .. ngx.escape_uri(image_id) .. "&format=svg"
  else
    url = image_png_url
  end

  local params = {
    method = "GET",
    keepalive = true,
    headers = {
      ["Origin"] = origin or "origin is missing",
    },
  }

  return botbye_http.request_uri(url, params, conf.connection_timeout)
end

-- Ensure derived URLs are initialised even if setConf is never called.
rebuildDerivedState()

return M
