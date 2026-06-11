-- Identity of this SDK build. Sent on every BotBye request via the Module-Name /
-- Module-Version headers and embedded in evaluate event payloads. Shared by the
-- protect (botbye) and phishing (botbye_phishing) modules, so it lives in its own
-- module rather than being private to either.
return {
  name = "OpenResty",
  version = "2.2.1",
}
