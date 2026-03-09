local conf = {
  endpoint = "",
  account_id = "",
  project_id = "",
  api_key = "",
  connection_timeout = 1000,
}

local M = {}

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
  
  -- Build URL with query parameters
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

  local httpc = require("resty.http").new()
  httpc:set_timeout(conf.connection_timeout)

  local res, err = httpc:request_uri(url, {
    method = "GET",
    keep_alive = true,
    headers = {
      ["X-Api-Key"] = conf.api_key,
      ["Origin"] = originValue,
    },
  })

  httpc:set_keepalive()

  return res, err
end

return M
