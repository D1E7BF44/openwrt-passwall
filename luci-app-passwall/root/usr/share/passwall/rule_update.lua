#!/usr/bin/lua

require 'luci.sys'
local luci = luci
local ucic = luci.model.uci.cursor()
local name = 'passwall'
local arg1 = arg[1]

local rule_path = "/usr/share/" .. name .. "/rules"
local reboot = 0
local gfwlist_update = 0
local chnroute_update = 0
local chnroute6_update = 0
local chnlist_update = 0

-- match comments/title/whitelist/ip address/excluded_domain
local comment_pattern = "^[!\\[@]+"
local ip_pattern = "^%d+%.%d+%.%d+%.%d+"
local domain_pattern = "([%w%-%_]+%.[%w%.%-%_]+)[%/%*]*"
local excluded_domain = {}

-- gfwlist parameter
local mydnsip = '127.0.0.1'
local mydnsport = '7913'
local ipsetname = 'gfwlist'

-- custom url
local enable_custom_url = 1
local gfwlist_url = ucic:get_first(name, 'global_rules', "gfwlist_url", "https://cdn.jsdelivr.net/gh/Loukky/gfwlist-by-loukky/gfwlist.txt")
local chnroute_url = ucic:get_first(name, 'global_rules', "chnroute_url", "https://example.com")
local chnroute6_url =  ucic:get_first(name, 'global_rules', "chnroute6_url", "https://example.com")
local chnlist_url_1 = 'https://cdn.jsdelivr.net/gh/felixonmars/dnsmasq-china-list/accelerated-domains.china.conf'
local chnlist_url_2 = 'https://cdn.jsdelivr.net/gh/felixonmars/dnsmasq-china-list/apple.china.conf'
local chnlist_url_3 = 'https://cdn.jsdelivr.net/gh/felixonmars/dnsmasq-china-list/google.china.conf'

local bc='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

-- base64decoding
local function base64_dec(data)
    data = string.gsub(data, '[^'..bc..'=]', '')
    return (data:gsub('.', function(x)
        if (x == '=') then return '' end
        local r,f='',(bc:find(x)-1)
        for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and '1' or '0') end
        return r;
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if (#x ~= 8) then return '' end
        local c=0
        for i=1,8 do c=c+(x:sub(i,i)=='1' and 2^(8-i) or 0) end
        return string.char(c)
    end))
end

local log = function(...)
    if arg1 then
        local result = os.date("%Y-%m-%d %H:%M:%S: ") .. table.concat({...}, " ")
        if arg1 == "log" then
            local f, err = io.open("/var/log/passwall.log", "a")
            if f and err == nil then
                f:write(result .. "\n")
                f:close()
            end
        elseif arg1 == "print" then
            print(result)
        end
    end
end

-- trim
local function trim(text)
    if not text or text == "" then return "" end
    return (string.gsub(text, "^%s*(.-)%s*$", "%1"))
end

-- wget
local function wget(url, file)
	local cmd = "/usr/bin/wget --no-check-certificate -t 3 -T 10 -O"
	if file then
		cmd = cmd .. " " .. file .. " " .. url
	else
		cmd = cmd .. "- " .. url
	end
	local stdout = luci.sys.exec(cmd)
    return trim(stdout)
end

-- curl
local function curl(url, file)
	local cmd = "curl -skL -w %{http_code} --retry 3 --connect-timeout 3 '" .. url .. "'"
	if file then
		cmd = cmd .. " -o " .. file
	end
	local stdout = luci.sys.exec(cmd)

	if file then
		return tonumber(trim(stdout))
	else
		return trim(stdout)
	end
end

local function fetch_gfwlist()
	local sret = curl(gfwlist_url, "/tmp/gfwlist.txt")
	if sret == 200 then
		local gfwlist = io.open("/tmp/gfwlist.txt", "r")
		local decode = base64_dec(gfwlist:read("*all"))
		gfwlist:close()
		gfwlist = io.open("/tmp/gfwlist.txt", "w")
		gfwlist:write(decode)
		gfwlist:close()
	end

	return sret;
end

local function fetch_chnroute()
	local sret = curl(chnroute_url, "/tmp/chnroute_tmp")
	return sret;
end

local function fetch_chnroute6()
	local sret = curl(chnroute6_url, "/tmp/chnroute6_tmp")
	return sret;
end

local function fetch_chnlist()
	local sret = 0
	local sret1 = curl(chnlist_url_1, "/tmp/chnlist_1")
	local sret2 = curl(chnlist_url_2, "/tmp/chnlist_2")
	local sret3 = curl(chnlist_url_3, "/tmp/chnlist_3")

	if sret1 == 200 and sret2 ==200 and sret3 == 200 then
		sret=200
	end
	return sret;
end

--check excluded domain
local function check_excluded_domain(value)
	for k,v in ipairs(excluded_domain) do
		if value:find(v) then
			return true
		end
	end
end

local function generate_gfwlist()
	local domains = {}
	local out = io.open("/tmp/gfwlist_tmp", "w")

	for line in io.lines("/tmp/gfwlist.txt") do
		if not (string.find(line, comment_pattern) or string.find(line, ip_pattern) or check_excluded_domain(line)) then
			local start, finish, match = string.find(line, domain_pattern)
			if (start) then
				domains[match] = true
			end
		end
	end

	for k,v in pairs(domains) do
		out:write(string.format("server=/.%s/%s#%s\n", k,mydnsip,mydnsport))
		out:write(string.format("ipset=/.%s/%s\n", k,ipsetname))
	end

	out:close()
end

local function generate_chnlist()
	local domains = {}
	local out = io.open("/tmp/cdn_tmp", "w")

	for line in io.lines("/tmp/chnlist_1") do
		local start, finish, match = string.find(line, domain_pattern)
		if (start) then
			domains[match] = true
		end
	end

	for line in io.lines("/tmp/chnlist_2") do
		local start, finish, match = string.find(line, domain_pattern)
		if (start) then
			domains[match] = true
		end
	end

	for line in io.lines("/tmp/chnlist_3") do
		local start, finish, match = string.find(line, domain_pattern)
		if (start) then
			domains[match] = true
		end
	end

	for k,v in pairs(domains) do
		out:write(string.format("%s\n", k))
	end

	out:close()

	luci.sys.call("cat /tmp/cdn_tmp | sort -u > /tmp/chnlist_tmp")
end

if arg[2] then
	if arg[2]:find("gfwlist") then
		gfwlist_update = 1
    end
	if arg[2]:find("chnroute") then
		chnroute_update = 1
    end
	if arg[2]:find("chnroute6") then
		chnroute6_update = 1
    end
	if arg[2]:find("chnlist") then
		chnlist_update = 1
	end
else
	gfwlist_update = ucic:get_first(name, 'global_rules', "gfwlist_update", 1)
	chnroute_update = ucic:get_first(name, 'global_rules', "chnroute_update", 1)
	chnroute6_update = ucic:get_first(name, 'global_rules', "chnroute6_update", 1)
	chnlist_update = ucic:get_first(name, 'global_rules', "chnlist_update", 1)
end
if gfwlist_update == 0 and chnroute_update == 0 and chnroute6_update == 0 and chnlist_update == 0 then
	os.exit(0)
end

log("Start updating rules...")
if tonumber(enable_custom_url) == 1 then
	local new_version = os.date("%Y-%m-%d")
	log("Custom rule address enabled...")
	if tonumber(gfwlist_update) == 1 then
		log("Start updating gfwlist...")
		local old_md5 = luci.sys.exec("echo -n $(md5sum " .. rule_path .. "/gfwlist.conf | awk '{print $1}')")
		local status = fetch_gfwlist()
		if status == 200 then
			generate_gfwlist()
			local new_md5 = luci.sys.exec("echo -n $([ -f '/tmp/gfwlist_tmp' ] && md5sum /tmp/gfwlist_tmp | awk '{print $1}')")
			if old_md5 ~= new_md5 then
				luci.sys.exec("mv -f /tmp/gfwlist_tmp " .. rule_path .. "/gfwlist.conf")
				ucic:set(name, ucic:get_first(name, 'global_rules'), "gfwlist_version", new_version)
				reboot = 1
				log("Successfully updated gfwlist...")
			else
				log("The gfwlist version is the same, no need to update.")
			end
		else
			log("Failed to download gfwlist file")
		end
		os.remove("/tmp/gfwlist.txt")
		os.remove("/tmp/gfwlist_tmp")
	end

	if tonumber(chnroute_update) == 1 then
		log("Start updating chnroute...")
		local old_md5 = luci.sys.exec("echo -n $(md5sum " .. rule_path .. "/chnroute | awk '{print $1}')")
		local status = fetch_chnroute()
		if status == 200 then
			local new_md5 = luci.sys.exec("echo -n $([ -f '/tmp/chnroute_tmp' ] && md5sum /tmp/chnroute_tmp | awk '{print $1}')")
			if old_md5 ~= new_md5 then
				luci.sys.exec("mv -f /tmp/chnroute_tmp " .. rule_path .. "/chnroute")
				ucic:set(name, ucic:get_first(name, 'global_rules'), "chnroute_version", new_version)
				reboot = 1
				log("Update chnroute successfully...")
			else
				log("The chnroute version is the same, no need to update.")
			end
		else
			log("chnroute file download failed")
		end
		os.remove("/tmp/chnroute_tmp")
	end

	if tonumber(chnroute6_update) == 1 then
		log("Start updating chnroute6...")
		local old_md5 = luci.sys.exec("echo -n $(md5sum " .. rule_path .. "/chnroute6 | awk '{print $1}')")
		local status = fetch_chnroute6()
		if status == 200 then
			local new_md5 = luci.sys.exec("echo -n $([ -f '/tmp/chnroute6_tmp' ] && md5sum /tmp/chnroute6_tmp | awk '{print $1}')")
			if old_md5 ~= new_md5 then
				luci.sys.exec("mv -f /tmp/chnroute6_tmp " .. rule_path .. "/chnroute6")
				ucic:set(name, ucic:get_first(name, 'global_rules'), "chnroute6_version", new_version)
				reboot = 1
				log("Update chnroute6 successfully...")
			else
				log("The chnroute6 version is the same, no need to update.")
			end
		else
			log("chnroute6 file download failed")
		end
		os.remove("/tmp/chnroute6_tmp")
	end
	
	if tonumber(chnlist_update) == 1 then
		log("Start updating chnlist...")
		local old_md5 = luci.sys.exec("echo -n $(md5sum " .. rule_path .. "/chnlist | awk '{print $1}')")
		local status = fetch_chnlist()
		if status == 200 then
			generate_chnlist()
			local new_md5 = luci.sys.exec("echo -n $([ -f '/tmp/chnlist_tmp' ] && md5sum /tmp/chnlist_tmp | awk '{print $1}')")
			if old_md5 ~= new_md5 then
				luci.sys.exec("mv -f /tmp/chnlist_tmp " .. rule_path .. "/chnlist")
				ucic:set(name, ucic:get_first(name, 'global_rules'), "chnlist_version", new_version)
				reboot = 1
				log("Update chnlist successfully...")
			else
				log("The chnlist version is the same, no need to update")
			end
		else
			log("chnlist file download failed")
		end
		os.remove("/tmp/chnlist_1")
		os.remove("/tmp/chnlist_2")
		os.remove("/tmp/chnlist_3")
		os.remove("/tmp/cdn_tmp")
		os.remove("/tmp/chnlist_tmp")
	end
end

ucic:set(name, ucic:get_first(name, 'global_rules'), "gfwlist_update", gfwlist_update)
ucic:set(name, ucic:get_first(name, 'global_rules'), "chnroute_update", chnroute_update)
ucic:set(name, ucic:get_first(name, 'global_rules'), "chnroute6_update", chnroute6_update)
ucic:set(name, ucic:get_first(name, 'global_rules'), "chnlist_update", chnlist_update)
ucic:save(name)
luci.sys.call("uci commit " .. name)

if reboot == 1 then
	log("Restart the service and apply the new rules")
	luci.sys.call("/usr/share/" .. name .. "/iptables.sh flush_ipset &&  /etc/init.d/" .. name .. " restart")
end
log("The rule script is executed...")
