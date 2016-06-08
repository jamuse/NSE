local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local ipOps = require "ipOps"

description =  [[
Determines if the web server leaks an internal IPv4 address via the F5 Big-IP
cookie.

F5 Big-IP load balancers encode the IP address and port of the destination
server within the BigIPServer<pool_name> cookie. When the server is not
configured to encrypt the cookie value, the encoded cookie discloses the
server's internal IP address.
]]

---
-- @usage nmap --script http-bigip-internal-ip-disclosure <target>
-- @usage nmap --script http-bigip-internal-ip-disclosure --script-args http-bigip-internal-ip-disclosure.path=/path <target>
--
-- @args http-bigip-internal-ip-disclosure.path Path to URI. Default: /
--
-- @output
-- 80/tcp open  http    syn-ack
-- | http-bigip-internal-ip-disclosure: 
-- |   Internal IP Leaked: 172.16.1.11
-- |_  Internal Port Leaked: 80
--
-- @xmloutput
-- <elem key="Internal IP Leaked">172.16.1.11</elem>
-- <elem key="Internal Port Leaked">80</elem>
---

author = "Josh Amishav-Zlatin"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = { "vuln", "discovery", "safe" } 

portrule = shortport.http

local function ReverseCookieValue(Value)
  if Value:match("^[%d.]+$") then
    -- Example value: 4225695754.20480.0000
    local ReverseIPDec = Value:match("%d+")
    local ReverseHexIP = string.format("%x", ReverseIPDec)
    local ROct1=ReverseHexIP:sub(7,8)
    local ROct2=ReverseHexIP:sub(5,6)
    local ROct3=ReverseHexIP:sub(3,4)
    local ROct4=ReverseHexIP:sub(1,2)
    local Oct1 = tonumber(ROct1,16)
    local Oct2 = tonumber(ROct2,16)
    local Oct3 = tonumber(ROct3,16)
    local Oct4 = tonumber(ROct4,16)
    local IP = Oct1 .. "."  .. Oct2 .. "." .. Oct3 .. "." .. Oct4

    -- Parse the port and reverse it
    local TmpPort = Value:match("%.%d+%.")
    local ReversePortDec = TmpPort:match("%d+")
    local RHexPort = string.format("%x", ReversePortDec)
    local POct1=RHexPort:sub(3,4)
    local POct2=RHexPort:sub(1,2)
    local HexPort = POct1 .. POct2
    local Port = tonumber(HexPort,16)

    return IP, Port
  elseif Value:match("00000000000000000000ffff") then
    -- Example value: rd554o00000000000000000000ffffac164811o5080
    local TempIP=Value:match("00000000000000000000ffff........");
    local HexIP = TempIP:sub(25,32)
    local Oct1 = HexIP:sub(1,2)
    local Oct2 = HexIP:sub(3,4)
    local Oct3 = HexIP:sub(5,6)
    local Oct4 = HexIP:sub(7,8)
    local IP = tonumber(Oct1,16) .. "." .. tonumber(Oct2,16) .. "." .. tonumber(Oct3,16) .. "." .. tonumber(Oct4,16)
    local TempPort = Value:match("o%d+$");
    local Port = TempPort:sub(2,-1)
    return IP, Port
  else
    return nil,nil
  end
end

action = function(host, port)
  local output = stdnse.output_table()
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
  local response = http.get(host, port, path, nil)

  for _, cookie in pairs(response.cookies) do --
    if cookie.name:find("BIGipServer") then
      stdnse.debug1("BigIPCookie: %s", cookie.value)
      local IP, Port = ReverseCookieValue(cookie.value)
      stdnse.debug1("Leaked IP: %s", IP)
      stdnse.debug1("Leaked Port: %s", Port)
      local PrivateIP, _ = ipOps.isPrivate(IP)
      if PrivateIP and IP ~= host.ip then
        output["Internal IP Leaked"] = IP 
        output["Internal Port Leaked"] = Port 
        return output
      end
    end
  end
end
