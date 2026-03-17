local http = require("resty.http")

local M = {}

function M.request_uri(url, opts, timeout)
  local httpc = http.new()
  if timeout then
    httpc:set_timeouts(timeout, timeout, timeout)
  end

  return httpc:request_uri(url, opts)
  -- request_uri() already handles keepalive/close internally
end

return M
