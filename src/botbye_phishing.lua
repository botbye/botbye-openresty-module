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

local function normalizeBaseUrl(url)
  return (url or ""):gsub("/+$", "")
end

local function buildPhishingUrl(pathAndQuery)
  local base = normalizeBaseUrl(conf.endpoint)
  return base .. pathAndQuery
end

function M.setConf(input_conf)
  for k, v in pairs(input_conf) do
    assertNotBlank(k, v)
    conf[k] = v
  end
end

function M.fetchImage(origin, image_id)
  local url = buildPhishingUrl(
    "/api/v1/phishing/" .. conf.account_id .. "/projects/" .. conf.project_id .. "/image"
  )

  local originValue = origin or "origin is missing"
  
  local queryParams = {}
  if image_id then
    table.insert(queryParams, "image_id=" .. ngx.escape_uri(image_id))
    table.insert(queryParams, "format=svg")
  else
    table.insert(queryParams, "format=png")
  end
  
  if #queryParams > 0 then
    url = url .. "?" .. table.concat(queryParams, "&")
  end

  local res, err = botbye_http.request_uri(url, {
    method = "GET",
    keep_alive = true,
    headers = {
      ["X-Api-Key"] = conf.api_key,
      ["Origin"] = originValue,
    },
  }, conf.connection_timeout)

  return res, err
end

return M
