local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description =  [[
Takes a screenshot of an HTTP interface using phantomjs.

Build instructions:
1. apt-get install build-essential chrpath libssl-dev libxft-dev libfreetype6 libfreetype6-dev libfontconfig1 libfontconfig1-dev

2. Download the latest version of phantomjs:
   http://phantomjs.org/download.html

3. Make sure to set the path to phantomjs and the ScreenCapture.js script or adjust the default values

]]

---
-- @usage nmap --script http-screenshot <target>
-- @usage nmap --script http-screenshot --script-args http-screenshot.opath=/path,http-screenshot.phantpath=/path,http-screenshot.screenpath=/path <target>
--
-- @args http-screenshot.opath Path used to save the image. Default: /tmp
-- @args http-screenshot.phantpath Path to phantomjs. Default: /usr/local/src/phantomjs-2.1.1-linux-x86_64/bin/
-- @args http-screenshot.screenpath Path to ScreenCapture.js. Default: /usr/local/bin
--
-- @output
-- 80/tcp open  http    syn-ack
-- | http-screenshot: 
-- |_  status: Saved to /tmp/screenshot-nmap-10.0.0.1:80.png
--
-- @xmloutput
-- <elem key="status">Saved to /tmp/screenshot-nmap-10.0.0.1:80.png</elem>
-- <elem key="status">DEBUG is enabled</elem>
---

author = "Josh Amishav-Zlatin"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

local function CreateHTML(InputPath, OutputFile)
  stdnse.debug1("InputPath: %s", InputPath )
  stdnse.debug1("OutputFile: %s", OutputFile )
  local cmd = "/usr/local/bin/PNG2HTML.sh " .. InputPath .." " .. OutputFile
  stdnse.debug1("Command: %s", cmd )
  local ret = os.execute(cmd)
  local msg = "Failed to take a screenshot"

  if ret then
    msg = "Final report saved to " .. OutputFile
    stdnse.debug1("Msg: %s", msg )
  end
  return msg
end

local function TakeScreenshot(target,port,prefix,opath,phantpath,screenpath)
  -- Screenshots will be called screenshot-<IP>:<port>.png
  stdnse.debug1("HostIP: %s", target )

  local filename = "screenshot-" .. target .. ":" .. port .. ".png"
  local dst = opath .. filename	

  -- Execute the shell command wkhtmltoimage-i386 <url> <filename>
  local cmd = phantpath .. "phantomjs " .. screenpath .. "ScreenCapture.js " .. prefix .. "://" .. target .. ":" .. port .. " " .. dst 
  stdnse.debug1("Command: %s", cmd )
  local ret = os.execute(cmd)
  local msg = "Failed to take a screenshot"

  if ret then
    msg = "Screenshot saved to " .. dst
    stdnse.debug1("Msg: %s", msg )
  end
  return msg
end

action = function(host, port)
  local opath = stdnse.get_script_args(SCRIPT_NAME .. ".opath") or "/tmp/"
  local ofile = stdnse.get_script_args(SCRIPT_NAME .. ".ofile") or "/var/www/preview.html"
  local phantpath = stdnse.get_script_args(SCRIPT_NAME .. ".phantpath") or "/usr/local/src/phantomjs-2.1.1-linux-x86_64/bin/"
  local screenpath = stdnse.get_script_args(SCRIPT_NAME .. ".screenpath") or "/usr/local/bin/"
  local table = stdnse.output_table()
  local target

  if host.targetname ~= nil and host.targetname ~= "" then
    target = host.targetname
  elseif host.name ~= nil and host.name ~= "" then
    target = host.name
  else
    target = host.ip
  end

  local msgStatus = TakeScreenshot(target,port.number,port.service,opath,phantpath,screenpath)
  local reportStatus=CreateHTML(opath, ofile)
  table.status = msgStatus
  table.report = reportStatus
  return table
end
