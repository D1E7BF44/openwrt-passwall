#!/usr/bin/lua

------------------------------------------------
-- @author William Chan <root@williamchan.me>
------------------------------------------------
require 'nixio'
require 'luci.model.uci'
require 'luci.util'
require 'luci.jsonc'
require 'luci.sys'
local api = require "luci.model.cbi.passwall.api.api"

-- these global functions are accessed all the time by the event handler
-- so caching them is worth the effort
local luci = luci
local tinsert = table.insert
local ssub, slen, schar, sbyte, sformat, sgsub = string.sub, string.len, string.char, string.byte, string.format, string.gsub
local jsonParse, jsonStringify = luci.jsonc.parse, luci.jsonc.stringify
local b64decode = nixio.bin.b64decode
local nodeResult = {} -- update result
local application = 'passwall'
local uciType = 'nodes'
local ucic2 = luci.model.uci.cursor()
local arg2 = arg[2]
local allowInsecure_default = ucic2:get_bool(application, "@global_subscribe[0]", "allowInsecure")
ucic2:revert(application)

local log = function(...)
	if arg2 then
		local result = os.date("%Y-%m-%d %H:%M:%S: ") .. table.concat({...}, " ")
		if arg2 == "log" then
			local f, err = io.open("/var/log/passwall.log", "a")
			if f and err == nil then
				f:write(result .. "\n")
				f:close()
			end
		elseif arg2 == "print" then
			print(result)
		end
	end
end

-- Get the current server of each dynamic configuration, you can use get and set, get must get the node table 
local CONFIG = {}

do
	local function import_config(protocol)
		local name = string.upper(protocol)
		local szType = "@global[0]"
		local option = protocol .. "_node"
		
		local node = ucic2:get(application, szType, option)
		local currentNode
		if node then
			currentNode = ucic2:get_all(application, node)
		end
		CONFIG[#CONFIG + 1] = {
			log = true,
			remarks = name .. "node",
			node = node,
			currentNode = currentNode,
			set = function(server)
				ucic2:set(application, szType, option, server)
			end
		}
	end
	import_config("tcp")
	import_config("udp")

	ucic2:foreach(application, "socks", function(t)
		local node = t.node
		local currentNode
		if node then
			currentNode = ucic2:get_all(application, node)
		end
		CONFIG[#CONFIG + 1] = {
			log = true,
			remarks = "Socks node" .. t[".name"],
			currentNode = currentNode,z
			set = function(server)
				ucic2:set(application, t[".name"], "node", server)
			end
		}
	end)

	local tcp_main = ucic2:get(application, "@auto_switch[0]", "tcp_main") or "nil"
	CONFIG[#CONFIG + 1] = {
		log = false,
		remarks = "Automatically switch TCP master node",
		currentNode = ucic2:get_all(application, tcp_main),
		set = function(server)
			ucic2:set(application, "@auto_switch[0]", "tcp_main1", server)
		end
	}

	local tcp_node_table = ucic2:get(application, "@auto_switch[0]", "tcp_node")
	if tcp_node_table then
		local nodes = {}
		local new_nodes = {}
		for k,v in ipairs(tcp_node_table) do
			local node = v
			local currentNode
			if node then
				currentNode = ucic2:get_all(application, node)
			end
			nodes[#nodes + 1] = {
				log = false,
				node = node,
				currentNode = currentNode,
				remarks = node,
				set = function(server)
					for kk, vv in pairs(CONFIG) do
						if (vv.remarks == "Automatically switch TCP_1 node list") then
							table.insert(vv.new_nodes, server)
						end
					end
				end
			}
		end
		CONFIG[#CONFIG + 1] = {
			remarks = "Automatically switch TCP node list",
			nodes = nodes,
			new_nodes = new_nodes,
			set = function()
				for kk, vv in pairs(CONFIG) do
					if (vv.remarks == "Automatically switch TCP_1 node list") then
						log("Refresh the auto switch list")
						ucic2:set_list(application, "@auto_switch[0]", "tcp_node", vv.new_nodes)
					end
				end
			end
		}
	end

	ucic2:foreach(application, uciType, function(node)
		if node.protocol and node.protocol == '_shunt' then
			local node_id = node[".name"]
			ucic2:foreach(application, "shunt_rules", function(e)
				local _node_id = node[e[".name"]] or nil
				local _node
				if _node_id then
					_node = ucic2:get_all(application, _node_id)
				end
				CONFIG[#CONFIG + 1] = {
					log = false,
					currentNode = _node,
					remarks = "Diversion" .. e.remarks .. "Node",
					set = function(server)
						ucic2:set(application, node_id, e[".name"], server)
					end
				}
			end)

			local default_node_id = node.default_node
			local default_node
			if default_node_id then
				default_node = ucic2:get_all(application, default_node_id)
			end
			CONFIG[#CONFIG + 1] = {
				log = false,
				currentNode = default_node,
				remarks = "Shunt default node",
				set = function(server)
					ucic2:set(application, node_id, "default_node", server)
				end
			}
		elseif node.protocol and node.protocol == '_balancing' then
			local node_id = node[".name"]
			local nodes = {}
			local new_nodes = {}
			if node.balancing_node then
				for k, v in pairs(node.balancing_node) do
					local node = v
					local currentNode
					if node then
						currentNode = ucic2:get_all(application, node)
					end
					nodes[#nodes + 1] = {
						log = false,
						node = node,
						currentNode = currentNode,
						remarks = node,
						set = function(server)
							for kk, vv in pairs(CONFIG) do
								if (vv.remarks == "Load balancing node list" .. node_id) then
									table.insert(vv.new_nodes, server)
								end
							end
						end
					}
				end
			end
			CONFIG[#CONFIG + 1] = {
				remarks = "Load balancing node list" .. node_id,
				nodes = nodes,
				new_nodes = new_nodes,
				set = function()
					for kk, vv in pairs(CONFIG) do
						if (vv.remarks == "Load Balancing Node List" .. node_id) then
							log("Refresh the list of load balancing nodes")
							ucic2:foreach(application, uciType, function(node2)
								if node2[".name"] == node[".name"] then
									local index = node2[".index"]
									ucic2:set_list(application, "@nodes[" .. index .. "]", "balancing_node", vv.new_nodes)
								end
							end)
						end
					end
				end
			}
		end
	end)

	for k, v in pairs(CONFIG) do
		if v.nodes and type(v.nodes) == "table" then
			for kk, vv in pairs(v.nodes) do
				if vv.currentNode == nil then
					CONFIG[k].nodes[kk] = nil
				end
			end
		else
			if v.currentNode == nil then
				CONFIG[k] = nil
			end
		end
	end
end

-- Determine whether to filter node keywords
local filter_keyword_enabled = ucic2:get(application, "@global_subscribe[0]", "filter_enabled")
local filter_keyword_table = ucic2:get(application, "@global_subscribe[0]", "filter_keyword")
local filter_keyword_discarded = ucic2:get(application, "@global_subscribe[0]", "filter_keyword_discarded")
local function is_filter_keyword(value)
	if filter_keyword_enabled and filter_keyword_enabled == "1" then
		if filter_keyword_table then
			if filter_keyword_discarded and filter_keyword_discarded == "1" then
				for k,v in ipairs(filter_keyword_table) do
					if value:find(v) then
						return true
					end
				end
			else
				local result = true
				for k,v in ipairs(filter_keyword_table) do
					if value:find(v) then
						result = false
					end
				end
				return result
			end
		end
	end
	return false
end

-- Split string
local function split(full, sep)
	if full then
		full = full:gsub("%z", "") -- It’s not very clear here, sometimes with a \0 at the end
		local off, result = 1, {}
		while true do
			local nStart, nEnd = full:find(sep, off)
			if not nEnd then
				local res = ssub(full, off, slen(full))
				if #res > 0 then -- Filter out \0
					tinsert(result, res)
				end
				break
			else
				tinsert(result, ssub(full, off, nStart - 1))
				off = nEnd + 1
			end
		end
		return result
	end
	return {}
end
-- urlencode
-- local function get_urlencode(c) return sformat("%%%02X", sbyte(c)) end

-- local function urlEncode(szText)
-- 	local str = szText:gsub("([^0-9a-zA-Z ])", get_urlencode)
-- 	str = str:gsub(" ", "+")
-- 	return str
-- end

local function get_urldecode(h) return schar(tonumber(h, 16)) end
local function UrlDecode(szText)
	return (szText and szText:gsub("+", " "):gsub("%%(%x%x)", get_urldecode)) or nil
end

-- trim
local function trim(text)
	if not text or text == "" then return "" end
	return (sgsub(text, "^%s*(.-)%s*$", "%1"))
end

-- base64
local function base64Decode(text)
	local raw = text
	if not text then return '' end
	text = text:gsub("%z", "")
	text = text:gsub("_", "/")
	text = text:gsub("-", "+")
	local mod4 = #text % 4
	text = text .. string.sub('====', mod4 + 1)
	local result = b64decode(text)
	if result then
		return result:gsub("%z", "")
	else
		return raw
	end
end
-- Data processing
local function processData(szType, content, add_mode)
	--log(content, add_mode)
	local result = {
		timeout = 60,
		add_mode = add_mode,
		is_sub = add_mode == 'Import' and 0 or 1
	}
	if szType == 'ssr' then
		local dat = split(content, "/%?")
		local hostInfo = split(dat[1], ':')
		result.type = "SSR"
		result.address = hostInfo[1]
		result.port = hostInfo[2]
		result.protocol = hostInfo[3]
		result.method = hostInfo[4]
		result.obfs = hostInfo[5]
		result.password = base64Decode(hostInfo[6])
		local params = {}
		for _, v in pairs(split(dat[2], '&')) do
			local t = split(v, '=')
			params[t[1]] = t[2]
		end
		result.obfs_param = base64Decode(params.obfsparam)
		result.protocol_param = base64Decode(params.protoparam)
		local group = base64Decode(params.group)
		if group then result.group = group end
		result.remarks = base64Decode(params.remarks)
	elseif szType == 'vmess' then
		local info = jsonParse(content)
		result.type = 'V2ray'
		if api.is_finded("xray") then
			result.type = 'Xray'
		end
		result.address = info.add
		result.port = info.port
		result.protocol = 'vmess'
		result.transport = info.net
		result.alter_id = info.aid
		result.uuid = info.id
		result.remarks = info.ps
		-- result.mux = 1
		-- result.mux_concurrency = 8
		if info.net == 'ws' then
			result.ws_host = info.host
			result.ws_path = info.path
		end
		if info.net == 'h2' then
			result.h2_host = info.host
			result.h2_path = info.path
		end
		if info.net == 'tcp' then
			if info.type and info.type ~= "http" then
				info.type = "none"
			end
			result.tcp_guise = info.type
			result.tcp_guise_http_host = info.host
			result.tcp_guise_http_path = info.path
		end
		if info.net == 'kcp' then
			result.mkcp_guise = info.type
			result.mkcp_mtu = 1350
			result.mkcp_tti = 50
			result.mkcp_uplinkCapacity = 5
			result.mkcp_downlinkCapacity = 20
			result.mkcp_readBufferSize = 2
			result.mkcp_writeBufferSize = 2
		end
		if info.net == 'quic' then
			result.quic_guise = info.type
			result.quic_key = info.key
			result.quic_security = info.securty
		end
		if not info.security then result.security = "auto" end
		if info.tls == "tls" or info.tls == "1" then
			result.tls = "1"
			result.tls_serverName = info.host
			result.tls_allowInsecure = allowInsecure_default and "1" or "0"
		else
			result.tls = "0"
		end
	elseif szType == "ss" then
		local idx_sp = 0
		local alias = ""
		if content:find("#") then
			idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
		end
		local info = content:sub(1, idx_sp - 1)
		local hostInfo = split(base64Decode(info), "@")
		local hostInfoLen = #hostInfo
		local host = nil
		local userinfo = nil
		if hostInfoLen > 2 then
			host = split(hostInfo[hostInfoLen], ":")
			userinfo = {}
			for i = 1, hostInfoLen - 1 do
				tinsert(userinfo, hostInfo[i])
			end
			userinfo = table.concat(userinfo, '@')
		else
			host = split(hostInfo[2], ":")
			userinfo = base64Decode(hostInfo[1])
		end
		local method = userinfo:sub(1, userinfo:find(":") - 1)
		local password = userinfo:sub(userinfo:find(":") + 1, #userinfo)
		result.remarks = UrlDecode(alias)
		result.type = "SS"
		result.address = host[1]
		if host[2] and host[2]:find("/%?") then
			local query = split(host[2], "/%?")
			result.port = query[1]
			local params = {}
			for _, v in pairs(split(query[2], '&')) do
				local t = split(v, '=')
				params[t[1]] = t[2]
			end
			if params.plugin then
				local plugin_info = UrlDecode(params.plugin)
				local idx_pn = plugin_info:find(";")
				if idx_pn then
					result.plugin = plugin_info:sub(1, idx_pn - 1)
					result.plugin_opts =
						plugin_info:sub(idx_pn + 1, #plugin_info)
				else
					result.plugin = plugin_info
				end
			end
			if result.plugin and result.plugin == "simple-obfs" then
				result.plugin = "obfs-local"
			end
		else
			result.port = host[2]
		end
		result.method = method
		result.password = password
	elseif szType == "trojan" then
		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.type = "Trojan-Plus"
		result.remarks = UrlDecode(alias)
		if content:find("@") then
			local Info = split(content, "@")
			result.password = UrlDecode(Info[1])
			local port = "443"
			Info[2] = (Info[2] or ""):gsub("/%?", "?")
			local hostInfo = nil
			if Info[2]:find(":") then
				hostInfo = split(Info[2], ":")
				result.address = hostInfo[1]
				local idx_port = 2
				if hostInfo[2]:find("?") then
					hostInfo = split(hostInfo[2], "?")
					idx_port = 1
				end
				if hostInfo[idx_port] ~= "" then port = hostInfo[idx_port] end
			else
				if Info[2]:find("?") then
					hostInfo = split(Info[2], "?")
				end
				result.address = hostInfo and hostInfo[1] or Info[2]
			end
			local peer, sni = nil, ""
			local allowInsecure = allowInsecure_default
			local query = split(Info[2], "?")
			local params = {}
			for _, v in pairs(split(query[2], '&')) do
				local t = split(v, '=')
				params[string.lower(t[1])] = UrlDecode(t[2])
			end
			if params.allowinsecure then
				allowInsecure = params.allowinsecure
			end
			if params.peer then peer = params.peer end
			sni = params.sni and params.sni or ""
			if params.mux and params.mux == "1" then result.mux = "1" end
			if params.ws and params.ws == "1" then
				result.trojan_transport = "ws"
				if params.wshost then result.ws_host = params.wshost end
				if params.wspath then result.ws_path = params.wspath end
				if sni == "" and params.wshost then sni = params.wshost end
			end
			if params.ss and params.ss == "1" then
				result.ss_aead = "1"
				if params.ssmethod then result.ss_aead_method = string.lower(params.ssmethod) end
				if params.sspasswd then result.ss_aead_pwd = params.sspasswd end
			end
			result.port = port
			if result.mux or result.trojan_transport == "ws" or result.ss_aead then
				result.type = "Trojan-Go"
				result.fingerprint = "firefox"
			end
			result.tls = '1'
			result.tls_serverName = peer and peer or sni
			result.tls_allowInsecure = allowInsecure and "1" or "0"
		end
	elseif szType == "trojan-go" then
		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.type = "Trojan-Go"
		result.remarks = UrlDecode(alias)
		if content:find("@") then
			local Info = split(content, "@")
			result.password = UrlDecode(Info[1])
			local port = "443"
			Info[2] = (Info[2] or ""):gsub("/%?", "?")
			local hostInfo = nil
			if Info[2]:find(":") then
				hostInfo = split(Info[2], ":")
				result.address = hostInfo[1]
				local idx_port = 2
				if hostInfo[2]:find("?") then
					hostInfo = split(hostInfo[2], "?")
					idx_port = 1
				end
				if hostInfo[idx_port] ~= "" then port = hostInfo[idx_port] end
			else
				if Info[2]:find("?") then
					hostInfo = split(Info[2], "?")
				end
				result.address = hostInfo and hostInfo[1] or Info[2]
			end
			local peer, sni = nil, ""
			local allowInsecure = allowInsecure_default
			local query = split(Info[2], "?")
			local params = {}
			for _, v in pairs(split(query[2], '&')) do
				local t = split(v, '=')
				params[string.lower(t[1])] = UrlDecode(t[2])
			end
			if params.allowinsecure then
				allowInsecure = params.allowinsecure
			end
			if params.peer then peer = params.peer end
			sni = params.sni and params.sni or ""
			if params.mux and params.mux == "1" then result.mux = "1" end
			if params.type and params.type == "ws" then
				result.trojan_transport = "ws"
				if params.host then result.ws_host = params.host end
				if params.path then result.ws_path = params.path end
				if sni == "" and params.host then sni = params.host end
			end
			if params.encryption and params.encryption:match('^ss;[^;:]*[;:].*$') then
				result.ss_aead = "1"
				result.ss_aead_method, result.ss_aead_pwd = params.encryption:match('^ss;([^;:]*)[;:](.*)$')
				result.ss_aead_method = string.lower(result.ss_aead_method)
			end
			result.port = port
			result.fingerprint = "firefox"
			result.tls = '1'
			result.tls_serverName = peer and peer or sni
			result.tls_allowInsecure = allowInsecure and "1" or "0"
		end
	elseif szType == "ssd" then
		result.type = "SS"
		result.address = content.server
		result.port = content.port
		result.password = content.password
		result.method = content.encryption
		result.plugin = content.plugin
		result.plugin_opts = content.plugin_options
		result.group = content.airport
		result.remarks = content.remarks
	else
		log('The node subscription of type'.. szType ..' is not supported temporarily, skip this node.")
		return nil
	end
	if not result.remarks or result.remarks == "" then
		if result.address and result.port then
			result.remarks = result.address .. ':' .. result.port
		else
			result.remarks = "NULL"
		end
	end
	return result
end

-- curl
local function curl(url)
	local ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36"
	local stdout = luci.sys.exec('curl -sL --user-agent "' .. ua .. '" -k --retry 3 --connect-timeout 3 "' .. url .. '"')
	return trim(stdout)
end

local function truncate_nodes()
	local function clear(type)
		local node_num = ucic2:get(application, "@global_other[0]", type .. "_node_num") or 1
		for i = 1, node_num, 1 do
			local node = ucic2:get(application, "@global[0]", type .. "_node" .. i)
			if node then
				local is_sub_node = ucic2:get(application, node, "is_sub") or 0
				if is_sub_node == "1" then
					ucic2:set(application, '@global[0]', type .. "_node" .. i, "nil")
				end
			end
		end
	end
	clear("tcp")
	clear("udp")

	ucic2:foreach(application, "socks", function(t)
		local node = t.node
		if node then
			local is_sub_node = ucic2:get(application, node, "is_sub") or 0
			if is_sub_node == "1" then
				ucic2:set(application, t[".name"], "node", "nil")
			end
		end
	end)

	ucic2:foreach(application, uciType, function(node)
		if (node.is_sub or node.hashkey) and node.add_mode ~= '导入' then
			ucic2:delete(application, node['.name'])
		end
	end)
	ucic2:commit(application)

	log('All online subscription nodes have been deleted')
end

local function select_node(nodes, config)
	local server
	if config.currentNode then
		--Special priority Diversion + Remarks
		if config.currentNode.protocol and config.currentNode.protocol == '_shunt' then
			for id, node in pairs(nodes) do
				if node.remarks == config.currentNode.remarks then
					log('Select ['.. config.remarks ..'] split matching node:' .. node.remarks)
					server = id
					break
				end
			end
		end
		-- Special priority load balancing + remarks
		if config.currentNode.protocol and config.currentNode.protocol == '_balancing' then
			for id, node in pairs(nodes) do
				if node.remarks == config.currentNode.remarks then
					log('Select ['.. config.remarks ..'] load balancing matching node:' .. node.remarks)
					server = id
					break
				end
			end
		end
		-- First priority cfgid
		if not server then
			for id, node in pairs(nodes) do
				if id == config.currentNode['.name'] then
					if config.log == nil or config.log == true then
						log('Select ['.. config.remarks ..'] the first matching node:' .. node.remarks)
					end
					server = id
					break
				end
			end
		end
		-- Second priority type + IP + port
		if not server then
			for id, node in pairs(nodes) do
				if node.type and node.address and node.port then
					if node.type == config.currentNode.type and (node.address .. ':' .. node.port == config.currentNode.address .. ':' .. config.currentNode.port) then
						if config.log == nil or config.log == true then
							log('Select ['.. config.remarks ..'] the second matching node:' .. node.remarks)
						end
						server = id
						break
					end
				end
			end
		end
		-- Third priority IP + port
		if not server then
			for id, node in pairs(nodes) do
				if node.address and node.port then
					if node.address .. ':' .. node.port == config.currentNode.address .. ':' .. config.currentNode.port then
						if config.log == nil or config.log == true then
							log('Select ['.. config.remarks ..'] the third matching node:' .. node.remarks)
						end
						server = id
						break
					end
				end
			end
		end
		-- Fourth priority IP
		if not server then
			for id, node in pairs(nodes) do
				if node.address then
					if node.address == config.currentNode.address then
						if config.log == nil or config.log == true then
							log('Select ['.. config.remarks ..'] the fourth matching node:' .. node.remarks)
						end
						server = id
						break
					end
				end
			end
		end
		-- Fifth priority note
		if not server then
			for id, node in pairs(nodes) do
				if node.remarks then
					if node.remarks == config.currentNode.remarks then
						if config.log == nil or config.log == true then
							log('Select ['.. config.remarks ..'] the fifth matching node:' .. node.remarks)
						end
						server = id
						break
					end
				end
			end
		end
	end
	-- Not yet, just find one
	if not server then
		server = ucic2:get_all(application, '@' .. uciType .. '[0]')
		if server then
			if config.log == nil or config.log == true then
				log('【'.. config.remarks ..'】' ..'The most matching node could not be found, currently it has been replaced with:' .. server.remarks)
			end
			server = server[".name"]
		end
	end
	if server then
		config.set(server)
	end
end

local function update_node(manual)
	if next(nodeResult) == nil then
		log("Update failed, no node information is available")
		return
	end
	-- delet all for subscribe nodes
	ucic2:foreach(application, uciType, function(node)
		-- If it is a manually imported node, it will not participate in the deletion
		if manual == 0 and (node.is_sub or node.hashkey) and node.add_mode ~= 'Import' then
			ucic2:delete(application, node['.name'])
		end
	end)
	for _, v in ipairs(nodeResult) do
		for _, vv in ipairs(v) do
			local uuid = api.gen_uuid()
			local cfgid = ucic2:section(application, uciType, uuid)
			cfgid = uuid
			for kkk, vvv in pairs(vv) do
				ucic2:set(application, cfgid, kkk, vvv)
			end
		end
	end
	ucic2:commit(application)

	if next(CONFIG) then
		local nodes = {}
		local ucic3 = luci.model.uci.cursor()
		ucic3:foreach(application, uciType, function(node)
			nodes[node['.name']] = node
		end)
		for _, config in pairs(CONFIG) do
			if config.nodes and type(config.nodes) == "table" then
				for kk, vv in pairs(config.nodes) do
					select_node(nodes, vv)
				end
				config.set()
			else
				select_node(nodes, config)
			end
		end

		--[[
		for k, v in pairs(CONFIG) do
			if type(v.new_nodes) == "table" and #v.new_nodes > 0 then
				for kk, vv in pairs(v.new_nodes) do
					print(vv)
				end
			else
				print(v.new_nodes)
			end
		end
		]]--

		ucic2:commit(application)
		--luci.sys.call("/etc/init.d/" .. application .. " restart > /dev/null 2>&1 &") -- 不加&的话日志会出现的更早
	end
end

local function parse_link(raw, remark, manual)
	if raw and #raw > 0 then
		local add_mode
		local nodes, szType
		local all_nodes = {}
		tinsert(nodeResult, all_nodes)
		-- SSD seems to start with this format ssd://
		if raw:find('ssd://') then
			szType = 'ssd'
			add_mode = remark
			local nEnd = select(2, raw:find('ssd://'))
			nodes = base64Decode(raw:sub(nEnd + 1, #raw))
			nodes = jsonParse(nodes)
			local extra = {
				airport = nodes.airport,
				port = nodes.port,
				encryption = nodes.encryption,
				password = nodes.password
			}
			local servers = {}
			-- Bread in SS
			for _, server in ipairs(nodes.servers) do
				tinsert(servers, setmetatable(server, { __index = extra }))
			end
			nodes = servers
		else
			-- Formats other than ssd
			if manual then
				nodes = split(raw:gsub(" ", "\n"), "\n")
				add_mode = 'Import'
			else
				nodes = split(base64Decode(raw):gsub(" ", "\n"), "\n")
				add_mode = remark
			end
		end

		for _, v in ipairs(nodes) do
			if v then
				local result
				if szType == 'ssd' then
					result = processData(szType, v, add_mode)
				elseif not szType then
					local node = trim(v)
					local dat = split(node, "://")
					if dat and dat[1] and dat[2] then
						if dat[1] == 'ss' or dat[1] == 'trojan' or dat[1] == 'trojan-go' then
							result = processData(dat[1], dat[2], add_mode)
						else
							result = processData(dat[1], base64Decode(dat[2]), add_mode)
						end
					end
				else
					log('Skip unknown types: ' .. szType)
				end
				-- log(result)
				if result then
					if (not manual and is_filter_keyword(result.remarks)) or
						not result.address or
						result.remarks == "NULL" or
						result.address:match("[^0-9a-zA-Z%-%_%.%s]") or -- No one uses Chinese domain names for addresses in Chinese, even if the Chinese domain has Puny Code SB airport
						not result.address:find("%.") or --Although there is no. It is also considered a domain, but no one would do it like this.
						result.address:sub(#result.address) == "." -- 结尾是.
					then
						log('Discard filter node: '.. result.type ..' node, ' .. result.remarks)
					else
						tinsert(all_nodes, result)
					end
				end
			end
		end
		log('Number of successfully resolved nodes: '.. #all_nodes)
	else
		if not manual then
			log('The content of the obtained node is empty...')
		end
	end
end

local execute = function()
	-- exec
	do
		ucic2:foreach(application, "subscribe_list", function(obj)
			local enabled = obj.enabled or nil
			if enabled and enabled == "1" then
				local remark = obj.remark
				local url = obj.url
				log('Subscribing: ' .. url)
				local raw = curl(url)
				parse_link(raw, remark)
			end
		end)
		-- diff
		update_node(0)
	end
end

if arg[1] then
	if arg[1] == "start" then
		local count = luci.sys.exec("echo -n $(uci show " .. application .. " | grep @subscribe_list | grep -c \"enabled='1'\")")
		if count and tonumber(count) > 0 then
			log('Start subscribing...')
			xpcall(execute, function(e)
				log(e)
				log(debug.traceback())
				log('v)
			end)
			log('Subscribed...')
		else
			log('Subscription not set or not enabled, please check the settings...')
		end
	elseif arg[1] == "add" then
		local f = assert(io.open("/tmp/links.conf", 'r'))
		local content = f:read('*all')
		f:close()
		local nodes = split(content:gsub(" ", "\n"), "\n")
		for _, raw in ipairs(nodes) do
			parse_link(raw, nil, 1)
		end
		update_node(1)
		luci.sys.call("rm -f /tmp/links.conf")
	elseif arg[1] == "truncate" then
		truncate_nodes()
	end
end
