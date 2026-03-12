local http = require("resty.http")

local M = {}

function M.request_uri(url, opts, timeout)
  local httpc = http.new()
  if timeout ~= nil then
    httpc:set_timeout(timeout)
  end

  local res, err = httpc:request_uri(url, opts)
  httpc:set_keepalive()

  return res, err
end

return M
