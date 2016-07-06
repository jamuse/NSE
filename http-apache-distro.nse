local shortport = require "shortport"
local stdnse = require "stdnse"
local banners = require "banners"

description =  [[
Determines the Linux distribution in use based on the Apache banner leaked.

By default, Apache servers leak their version information within the Server response header. This script maps the version information leaked back to the underlying Linux distribution used.
]]

---
-- @usage nmap --script http-apache-distro <target>
--
-- @output
-- 80/tcp open  http    syn-ack ttl 39 Apache httpd 2.2.15 ((CentOS))
-- | http-distro: 
-- |_  os: CentOS 6
--
-- @xmloutput
-- <elem key="os">CentOS 6</elem>
---

author = "Josh Amishav-Zlatin"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = { "safe", "discovery" } 

portrule = shortport.http

action = function(host, port)
  local server = stdnse.output_table()
  local sig = port.version.product .. " " .. port.version.version .. " " .. port.version.extrainfo
  local distro = banners.lookupDistro(sig)
  if distro then
    server.os = distro
    return server
  end
--for k,v in pairs(map) do if s:match(k) then print(map[k]) end end
end
