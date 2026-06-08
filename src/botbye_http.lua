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

-- Normalise a transport error into the SDK-wide vocabulary shared with the other
-- botbye SDKs (kotlin/java/php) and across the protect + phishing flows:
-- "timeout" / "connection error" / "invalid json response". lua-resty-http surfaces
-- raw signals like "closed" or "connection refused" that must map onto the same
-- words so cross-SDK responses stay equal.
--
-- `fallback` is returned when nothing matches (and when `err` is not a string):
--   phishing passes nil  -> unmatched errors pass through verbatim;
--   protect passes "connection error" -> the evaluate path never leaks a raw
--   transport message (preserves its original catch-all behaviour).
function M.classifyError(err, fallback)
  if type(err) ~= "string" then return fallback or err end
  local lower = err:lower()
  if lower:find("timeout", 1, true) or lower:find("timed out", 1, true) or lower:find("idle", 1, true) then
    return "timeout"
  end
  if lower:find("connect", 1, true) or lower:find("refused", 1, true) or lower:find("closed", 1, true)
      or lower:find("reset", 1, true) or lower:find("empty reply", 1, true)
      or lower:find("end of stream", 1, true) or lower:find("broken pipe", 1, true) then
    return "connection error"
  end
  if lower:find("json", 1, true) or lower:find("decode", 1, true) or lower:find("parse", 1, true) then
    return "invalid json response"
  end
  if fallback ~= nil then return fallback end
  return err
end

return M
