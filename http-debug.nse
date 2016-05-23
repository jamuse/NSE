description =  [[
Sends an HTTP DEBUG request and shows if the DEBUG method is enabled.

The DEBUG verb is used within ASP.NET applications to start/stop remote debugging sessions.
]]

---
-- @usage
-- nmap --script http-debug -d <ip>
--
-- @output
-- 80/tcp open  http    syn-ack
-- | http-debug: DEBUG method is enabled
--
-- @args http-debug.path Path to URI


author = "Josh Amishav-Zlatin"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = { "vuln", "discovery", "safe" } 

local shortport = require 'shortport' 
local testlib = require "testlib"
local stdnse = require "stdnse"
local http = require "http"

portrule = shortport.http

local function generate_http_debug_req(host, port, path)
  local status = "disabled"
  local options = {header={}}
  options["header"]["Command"] = "stop-debug"

  -- send DEBUG request with stop-debug command
  local req = http.generic_request(host, port, "DEBUG", path, options)
  if (req.status == 301 or req.status == 302) and req.header["location"] then
    req = http.generic_request(host, port, "DEBUG", req.header["location"],options)
  end

  stdnse.debug1("Response body: %s", req.body )
  if req.body:match("OK") then
    status = "enabled"
  end
  return status
end

action = function(host, port)
  local path = stdnse.get_script_args("http-debug.path") or "/"
  status = generate_http_debug_req(host, port, path)
  if status == "enabled" then
    local response = "DEBUG method is enabled"
    return response
  end
end

