#!/bin/sh

IPSET_LANIPLIST="laniplist"
IPSET_VPSIPLIST="vpsiplist"
IPSET_SHUNTLIST="shuntlist"
IPSET_GFW="gfwlist"
#IPSET_GFW6="gfwlist6"
IPSET_CHN="chnroute"
IPSET_CHN6="chnroute6"
IPSET_BLACKLIST="blacklist"
IPSET_BLACKLIST2="blacklist2"
IPSET_BLACKLIST3="blacklist3"
IPSET_WHITELIST="whitelist"

FORCE_INDEX=2

ipt_n="iptables -t nat"
ipt_m="iptables -t mangle"
ip6t_n="ip6tables -t nat"
ip6t_m="ip6tables -t mangle"
FWI=$(uci -q get firewall.passwall.path 2>/dev/null)

factor() {
	if [ -z "$1" ] || [ -z "$2" ]; then
		echo ""
	elif [ "$1" == "1:65535" ]; then
		echo ""
	else
		echo "$2 $1"
	fi
}

dst() {
	echo "-m set $2 --match-set $1 dst"
}

comment() {
	local name=$(echo $1 | sed 's/ /_/g')
	echo "-m comment --comment '$name'"
}

RULE_LAST_INDEX() {
	[ $# -ge 3 ] || {
		echolog "The index enumeration method is incorrect (iptables), terminate the execution!"
		exit 1
	}
	local ipt_tmp=${1}; shift
	local chain=${1}; shift
	local list=${1}; shift
	local default=${1:-0}; shift
	local _index=$($ipt_tmp -n -L $chain --line-numbers 2>/dev/null | grep "$list" | sed -n '$p' | awk '{print $1}')
	echo "${_index:-${default}}"
}

REDIRECT() {
	local redirect="-j REDIRECT --to-ports $1"
	[ "$2" == "TPROXY" ] && redirect="-j TPROXY --tproxy-mark 0x1/0x1 --on-port $1"
	[ "$2" == "MARK" ] && redirect="-j MARK --set-mark $1"
	echo $redirect
}

get_redirect_ipt() {
	case "$1" in
	disable)
		echo "-j RETURN"
		;;
	global)
		echo "$(REDIRECT $2 $3)"
		;;
	gfwlist)
		echo "$(dst $IPSET_GFW) $(REDIRECT $2 $3)"
		;;
	chnroute)
		echo "$(dst $IPSET_CHN !) $(REDIRECT $2 $3)"
		;;
	returnhome)
		echo "$(dst $IPSET_CHN) $(REDIRECT $2 $3)"
		;;
	esac
}

get_action_chain_name() {
	case "$1" in
	disable)
		echo "No proxy"
		;;
	global)
		echo "Global proxy"
		;;
	gfwlist)
		echo "gfwlist"
		;;
	chnroute)
		echo "chnroute"
		;;
	returnhome)
		echo "chn list"
		;;
	esac
}

gen_laniplist() {
	cat <<-EOF
		0.0.0.0/8
		10.0.0.0/8
		100.64.0.0/10
		127.0.0.0/8
		169.254.0.0/16
		172.16.0.0/12
		192.168.0.0/16
		224.0.0.0/4
		240.0.0.0/4
	EOF
}

load_acl() {
	local items=$(get_enabled_anonymous_secs "@acl_rule")
	[ -n "$items" ] && {
		local item enabled remarks ip mac tcp_proxy_mode udp_proxy_mod
		local tcp_node udp_node tcp_no_redir_ports udp_no_redir_ports tcp_redir_ports udp_redir_ports
		local TCP_NODE UDP_NODE TCP_NODE_TYPE UDP_NODE_TYPE ipt_tmp is_tproxy tcp_port udp_port msg msg2
		echolog "Access control:"
		for item in $items; do
			unset ip mac tcp_port udp_port is_tproxy msg
			eval $(uci -q show "${CONFIG}.${item}" | cut -d'.' -sf 3-)
			[ -z "${ip}${mac}" ] && continue
			tcp_proxy_mode=${tcp_proxy_mode:-default}
			udp_proxy_mode=${udp_proxy_mode:-default}
			tcp_no_redir_ports=${tcp_no_redir_ports:-default}
			udp_no_redir_ports=${udp_no_redir_ports:-default}
			tcp_redir_ports=${tcp_redir_ports:-default}
			udp_redir_ports=${udp_redir_ports:-default}
			[ "$tcp_proxy_mode" = "default" ] && tcp_proxy_mode=$TCP_PROXY_MODE
			[ "$udp_proxy_mode" = "default" ] && udp_proxy_mode=$UDP_PROXY_MODE
			[ "$tcp_no_redir_ports" = "default" ] && tcp_no_redir_ports=$TCP_NO_REDIR_PORTS
			[ "$udp_no_redir_ports" = "default" ] && udp_no_redir_ports=$UDP_NO_REDIR_PORTS
			[ "$tcp_redir_ports" = "default" ] && tcp_redir_ports=$TCP_REDIR_PORTS
			[ "$udp_redir_ports" = "default" ] && udp_redir_ports=$UDP_REDIR_PORTS
			
			#echolog "Access control: ${item}..."
			[ -n "$ip" ] && msg="IP：$ip，"
			[ -n "$mac" ] && msg="${msg:+${msg} and }MAC：$mac，"
			ipt_tmp=$ipt_n
			[ "$tcp_proxy_mode" != "disable" ] && {
				[ "$TCP_NODE" != "nil" ] && {
					tcp_port=$TCP_REDIR_PORT
					eval TCP_NODE_TYPE=$(echo $(config_n_get $TCP_NODE type) | tr 'A-Z' 'a-z')
					[ "$TCP_NODE_TYPE" == "brook" ] && [ "$(config_n_get $TCP_NODE protocol client)" == "client" ] && is_tproxy=1
					#[ "$TCP_NODE_TYPE" == "trojan-go" ] && is_tproxy=1
					msg2="${msg}Use TCP node [$(get_action_chain_name $tcp_proxy_mode)]"
					if [ -n "${is_tproxy}" ]; then
						msg2="${msg2}(TPROXY:${tcp_port}) proxy"
						ipt_tmp=$ipt_m && is_tproxy="TPROXY"
					else
						msg2="${msg2}(REDIRECT:${tcp_port}) proxy"
					fi
					[ "$tcp_no_redir_ports" != "disable" ] && {
						$ipt_tmp -A PSW $(comment "$remarks") $(factor $ip "-s") $(factor $mac "-m mac --mac-source") -p tcp -m multiport --dport $tcp_no_redir_ports -j RETURN
						msg2="${msg2}[$?] Except ${tcp_no_redir_ports}"
					}
					msg2="${msg2} all ports"
					$ipt_tmp -A PSW $(comment "$remarks") -p tcp $(factor $ip "-s") $(factor $mac "-m mac --mac-source") $(factor $tcp_redir_ports "-m multiport --dport") $(dst $IPSET_SHUNTLIST) $(REDIRECT $tcp_port $is_tproxy)
					$ipt_tmp -A PSW $(comment "$remarks") -p tcp $(factor $ip "-s") $(factor $mac "-m mac --mac-source") $(factor $tcp_redir_ports "-m multiport --dport") $(dst $IPSET_BLACKLIST) $(REDIRECT $tcp_port $is_tproxy)
					$ipt_tmp -A PSW $(comment "$remarks") -p tcp $(factor $ip "-s") $(factor $mac "-m mac --mac-source") $(factor $tcp_redir_ports "-m multiport --dport") $(get_redirect_ipt $tcp_proxy_mode $tcp_port $is_tproxy)
				}
				echolog "  - ${msg2}"
			}
			$ipt_tmp -A PSW $(comment "$remarks") $(factor $ip "-s") $(factor $mac "-m mac --mac-source") -p tcp -j RETURN
			
			[ "$udp_proxy_mode" != "disable" ] && {
				msg2="${msg}Use UDP node [$(get_action_chain_name $udp_proxy_mode)]"
				[ "$UDP_NODE" != "nil" ] && {
					udp_port=$UDP_REDIR_PORT
					msg2="${msg2}(TPROXY:${udp_port}) proxy"
					[ "$udp_no_redir_ports" != "disable" ] && {
						$ipt_m -A PSW $(comment "$remarks") $(factor $ip "-s") $(factor $mac "-m mac --mac-source") -p udp -m multiport --dport $udp_no_redir_ports -j RETURN
						msg2="${msg2}[$?] Except ${udp_no_redir_ports}"
					}
					msg2="${msg2} all ports"
					$ipt_m -A PSW $(comment "$remarks") -p udp $(factor $ip "-s") $(factor $mac "-m mac --mac-source") $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_SHUNTLIST) $(REDIRECT $udp_port TPROXY)
					$ipt_m -A PSW $(comment "$remarks") -p udp $(factor $ip "-s") $(factor $mac "-m mac --mac-source") $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_BLACKLIST) $(REDIRECT $udp_port TPROXY)
					$ipt_m -A PSW $(comment "$remarks") -p udp $(factor $ip "-s") $(factor $mac "-m mac --mac-source") $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(get_redirect_ipt $udp_proxy_mode $udp_port TPROXY)
				}
				echolog "  - ${msg2}"
			}
			$ipt_m -A PSW $(comment "$remarks") $(factor $ip "-s") $(factor $mac "-m mac --mac-source") -p udp -j RETURN
		done
	}

	#  Load TCP default proxy mode
	local ipt_tmp=$ipt_n
	local is_tproxy msg
	unset is_tproxy msg

	if [ "$TCP_PROXY_MODE" != "disable" ]; then
		[ "$TCP_NO_REDIR_PORTS" != "disable" ] && $ipt_tmp -A PSW $(comment "default") -p tcp -m multiport --dport $TCP_NO_REDIR_PORTS -j RETURN
		ipt_tmp=$ipt_n
		unset is_tproxy msg
		[ "$TCP_NODE" != "nil" ] && {
			local TCP_NODE_TYPE=$(echo $(config_n_get $TCP_NODE type) | tr 'A-Z' 'a-z')
			[ "$TCP_NODE_TYPE" == "brook" ] && [ "$(config_n_get $TCP_NODE protocol client)" == "client" ] && is_tproxy=1
			#[ "$TCP_NODE_TYPE" == "trojan-go" ] && is_tproxy=1
				msg="TCP default proxy: use TCP node [$(get_action_chain_name $TCP_PROXY_MODE)]"
			if [ -n "$is_tproxy" ]; then
				ipt_tmp=$ipt_m && is_tproxy="TPROXY"
				msg="${msg}(TPROXY:${TCP_REDIR_PORT}) proxy"
			else
				msg="${msg}(REDIRECT:${TCP_REDIR_PORT}) proxy"
			fi
			[ "$TCP_NO_REDIR_PORTS" != "disable" ] && msg="${msg} except ${TCP_NO_REDIR_PORTS}"
			msg="${msg} all ports"
			$ipt_tmp -A PSW $(comment "default") -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_SHUNTLIST) $(REDIRECT $TCP_REDIR_PORT $is_tproxy)
			$ipt_tmp -A PSW $(comment "default") -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_BLACKLIST) $(REDIRECT $TCP_REDIR_PORT $is_tproxy)
			$ipt_tmp -A PSW $(comment "default") -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(get_redirect_ipt $TCP_PROXY_MODE $TCP_REDIR_PORT $is_tproxy)
			echolog "${msg}"
		}
	fi
	$ipt_n -A PSW $(comment "default") -p tcp -j RETURN
	$ipt_m -A PSW $(comment "default") -p tcp -j RETURN

	#  Load UDP default proxy mode
	if [ "$UDP_PROXY_MODE" != "disable" ]; then
		[ "$UDP_NO_REDIR_PORTS" != "disable" ] && $ipt_m -A PSW $(comment "default") -p udp -m multiport --dport $UDP_NO_REDIR_PORTS -j RETURN
		[ "$UDP_NODE" != "nil" ] && {
			msg="UDP default proxy: use UDP node [$(get_action_chain_name $UDP_PROXY_MODE)](TPROXY:${UDP_REDIR_PORT}) proxy"
			[ "$UDP_NO_REDIR_PORTS" != "disable" ] && msg="${msg} except ${UDP_NO_REDIR_PORTS}"
			msg="${msg}All ports"
			$ipt_m -A PSW $(comment "default") -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_SHUNTLIST) $(REDIRECT $UDP_REDIR_PORT TPROXY)
			$ipt_m -A PSW $(comment "default") -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_BLACKLIST) $(REDIRECT $UDP_REDIR_PORT TPROXY)
			$ipt_m -A PSW $(comment "default") -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(get_redirect_ipt $UDP_PROXY_MODE $UDP_REDIR_PORT TPROXY)
			echolog "${msg}"
		}
	fi
	$ipt_m -A PSW $(comment "default") -p udp -j RETURN
}

filter_haproxy() {
	uci show $CONFIG | grep "@haproxy_config" | grep "lbss=" | cut -d "'" -f 2 | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | awk -F ":" '{print $1}' | sed -e "/^$/d" | sed -e "s/^/add $IPSET_VPSIPLIST &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
	for host in $(uci show $CONFIG | grep "@haproxy_config" | grep "lbss=" | cut -d "'" -f 2 | grep -v -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | awk -F ":" '{print $1}'); do
		ipset -q add $IPSET_VPSIPLIST $(get_host_ip ipv4 $host 1)
	done
	echolog "Add the load balancing node to the ipset[$IPSET_VPSIPLIST] direct connection is completed"
}

filter_vpsip() {
	uci show $CONFIG | grep ".address=" | cut -d "'" -f 2 | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | sed -e "/^$/d" | sed -e "s/^/add $IPSET_VPSIPLIST &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
	#uci show $CONFIG | grep ".address=" | cut -d "'" -f 2 | grep -E "([[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){0,7}::[a-f0-9]{0,4}(:[a-f0-9]{1,4}){0,7}])" | sed -e "/^$/d" | sed -e "s/^/add $IPSET_VPSIP6LIST &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
	echolog "Add all nodes to ipset[$IPSET_VPSIPLIST] direct connection is completed"
}

filter_node() {
	local proxy_node=${1}
	local stream=$(echo ${2} | tr 'A-Z' 'a-z')
	local proxy_port=${3}

	filter_rules() {
		local node=${1}
		local stream=${2}
		local _proxy=${3}
		local _port=${4}
		local is_tproxy ipt_tmp ip6t_tmp msg msg2

		if [ -n "$node" ] && [ "$node" != "nil" ]; then
			local type=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
			local address=$(config_n_get $node address)
			local port=$(config_n_get $node port)
			ipt_tmp=$ipt_n
			ip6t_tmp=$ip6t_n
			[ "$stream" == "udp" ] && is_tproxy=1
			[ "$type" == "brook" ] && [ "$(config_n_get $node protocol client)" == "client" ] && is_tproxy=1
			#[ "$type" == "trojan-go" ] && is_tproxy=1
			if [ -n "$is_tproxy" ]; then
				ipt_tmp=$ipt_m
				ip6t_tmp=$ip6t_m
				msg="TPROXY"
			else
				msg="REDIRECT"
			fi
		else
			echolog "  - The node configuration is not normal, skip it"
			return 0
		fi

		local ADD_INDEX=$FORCE_INDEX
		for _ipt in 4 6; do
			[ "$_ipt" == "4" ] && _ipt=$ipt_tmp
			[ "$_ipt" == "6" ] && _ipt=$ip6t_tmp
			$_ipt -n -L PSW_OUTPUT | grep -q "${address}:${port}"
			if [ $? -ne 0 ]; then
				unset dst_rule
				local dst_rule=$(REDIRECT 1 MARK)
				msg2="Route by rule(${msg})"
				[ "$_ipt" == "$ipt_m" -o "$_ipt" == "$ip6t_m" ] || {
					dst_rule=$(REDIRECT $_port)
					msg2="Matryoshka use (${msg}:${port} -> ${_port})"
				}
				[ -n "$_proxy" ] && [ "$_proxy" == "1" ] && [ -n "$_port" ] || {
					ADD_INDEX=$(RULE_LAST_INDEX "$_ipt" PSW_OUT_PUT "$IPSET_VPSIPLIST" $FORCE_INDEX)
					dst_rule=" -j RETURN"
					msg2="Direct"
				}
				$_ipt -I PSW_OUTPUT $ADD_INDEX $(comment "${address}:${port}") -p $stream -d $address --dport $port $dst_rule 2>/dev/null
			#else
			#	msg2="Configured nodes,"
			fi
		done
		msg="[$?]$(echo ${2} | tr 'a-z' 'A-Z')${msg2}Use chain ${ADD_INDEX}, node（${type}）：${address}:${port}"
		echolog "  - ${msg}"
	}
	
	local proxy_protocol=$(config_n_get $proxy_node protocol)
	local proxy_type=$(echo $(config_n_get $proxy_node type nil) | tr 'A-Z' 'a-z')
	[ "$proxy_type" == "nil" ] && echolog " - The node configuration is abnormal, skip it：${proxy_node}" && return 0
	if [ "$proxy_protocol" == "_balancing" ]; then
		#echolog "  - Multi-node load balancing (${proxy_type}）..."
		proxy_node=$(config_n_get $proxy_node balancing_node)
		for _node in $proxy_node; do
			filter_rules "$_node" "$stream"
		done
	elif [ "$proxy_protocol" == "_shunt" ]; then
		#echolog "  - Diversion according to the requested destination address (${proxy_type}）..."
		local default_node=$(config_n_get $proxy_node default_node nil)
		local default_proxy=$(config_n_get $proxy_node default_proxy 0)
		if [ "$default_proxy" == 1 ]; then
			local main_node=$(config_n_get $proxy_node main_node nil)
			filter_rules $main_node $stream
		else
			filter_rules $default_node $stream
		fi
:<<!
		local default_node_address=$(get_host_ip ipv4 $(config_n_get $default_node address) 1)
		local default_node_port=$(config_n_get $default_node port)
		
		local shunt_ids=$(uci show $CONFIG | grep "=shunt_rules" | awk -F '.' '{print $2}' | awk -F '=' '{print $1}')
		for shunt_id in $shunt_ids; do
			#local shunt_proxy=$(config_n_get $proxy_node "${shunt_id}_proxy" 0)
			local shunt_proxy=0
			local shunt_node=$(config_n_get $proxy_node "${shunt_id}" nil)
			[ "$shunt_node" != "nil" ] && {
				[ "$shunt_proxy" == 1 ] && {
					local shunt_node_address=$(get_host_ip ipv4 $(config_n_get $shunt_node address) 1)
					local shunt_node_port=$(config_n_get $shunt_node port)
					[ "$shunt_node_address" == "$default_node_address" ] && [ "$shunt_node_port" == "$default_node_port" ] && {
						shunt_proxy=0
					}
				}
				filter_rules "$(config_n_get $proxy_node $shunt_id)" "$stream" "$shunt_proxy" "$proxy_port"
			}
		done
!
	else
		#echolog "  - Normal node（${proxy_type}）..."
		filter_rules "$proxy_node" "$stream"
	fi
}

dns_hijack() {
	$ipt_n -I PSW -p udp --dport 53 -j REDIRECT --to-ports 53
	echolog "Forcibly forward the request of the local DNS port UDP/53[$?]"
}

add_firewall_rule() {
	echolog "Start loading firewall rules..."
	ipset -! create $IPSET_LANIPLIST nethash
	ipset -! create $IPSET_VPSIPLIST nethash
	ipset -! create $IPSET_SHUNTLIST nethash
	ipset -! create $IPSET_GFW nethash
	#ipset -! create $IPSET_GFW6 nethash family inet6
	ipset -! create $IPSET_CHN nethash
	ipset -! create $IPSET_CHN6 nethash family inet6
	ipset -! create $IPSET_BLACKLIST nethash
	ipset -! create $IPSET_BLACKLIST2 nethash
	ipset -! create $IPSET_BLACKLIST3 nethash
	ipset -! create $IPSET_WHITELIST nethash

	local shunt_ids=$(uci show $CONFIG | grep "=shunt_rules" | awk -F '.' '{print $2}' | awk -F '=' '{print $1}')
	for shunt_id in $shunt_ids; do
		config_n_get $shunt_id ip_list | tr -s "\r\n" "\n" | sed -e "/^$/d" | sed -e "s/^/add $IPSET_SHUNTLIST &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
	done
	cat $RULES_PATH/chnroute | sed -e "/^$/d" | sed -e "s/^/add $IPSET_CHN &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
	cat $RULES_PATH/chnroute6 | sed -e "/^$/d" | sed -e "s/^/add $IPSET_CHN6 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
	cat $RULES_PATH/proxy_ip | sed -e "/^$/d" | sed -e "s/^/add $IPSET_BLACKLIST &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
	[ -f "$RULES_PATH/proxy_ip2" ] && cat $RULES_PATH/proxy_ip2 | sed -e "/^$/d" | sed -e "s/^/add $IPSET_BLACKLIST2 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
	[ -f "$RULES_PATH/proxy_ip3" ] && cat $RULES_PATH/proxy_ip3 | sed -e "/^$/d" | sed -e "s/^/add $IPSET_BLACKLIST3 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
	cat $RULES_PATH/direct_ip | sed -e "/^$/d" | sed -e "s/^/add $IPSET_WHITELIST &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R

	ipset -! -R <<-EOF
		$(gen_laniplist | sed -e "s/^/add $IPSET_LANIPLIST /")
	EOF
	[ $? -eq 0 ] || {
		echolog "The system is not compatible, terminate the execution!"
		return 1
	}
	
	# Ignore special IP segments
	local lan_ifname lan_ip
	lan_ifname=$(uci -q -p /var/state get network.lan.ifname)
	[ -n "$lan_ifname" ] && {
		lan_ip=$(ip address show $lan_ifname | grep -w "inet" | awk '{print $2}')
		echolog "Local network segment mutual access and direct connection:${lan_ip}"
		[ -n "$lan_ip" ] && ipset -! add $IPSET_LANIPLIST $lan_ip >/dev/null 2>&1 &
	}

	local ISP_DNS=$(cat $RESOLVFILE 2>/dev/null | grep -E -o "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sort -u | grep -v 0.0.0.0 | grep -v 127.0.0.1)
	[ -n "$ISP_DNS" ] && {
		echolog "Handling ISP DNS exceptions..."
		for ispip in $ISP_DNS; do
			ipset -! add $IPSET_WHITELIST $ispip >/dev/null 2>&1 &
			echolog "  - Append to the whitelist:${ispip}"
		done
	}
	
	#  Filter all node IP
	filter_vpsip > /dev/null 2>&1 &
	filter_haproxy > /dev/null 2>&1 &
	
	$ipt_n -N PSW
	$ipt_n -A PSW $(dst $IPSET_LANIPLIST) -j RETURN
	$ipt_n -A PSW $(dst $IPSET_VPSIPLIST) -j RETURN
	$ipt_n -A PSW $(dst $IPSET_WHITELIST) -j RETURN
	
	$ipt_n -N PSW_OUTPUT
	$ipt_n -A PSW_OUTPUT $(dst $IPSET_LANIPLIST) -j RETURN
	$ipt_n -A PSW_OUTPUT $(dst $IPSET_VPSIPLIST) -j RETURN
	$ipt_n -A PSW_OUTPUT $(dst $IPSET_WHITELIST) -j RETURN

	$ipt_m -N PSW
	$ipt_m -A PSW $(dst $IPSET_LANIPLIST) -j RETURN
	$ipt_m -A PSW $(dst $IPSET_VPSIPLIST) -j RETURN
	$ipt_m -A PSW $(dst $IPSET_WHITELIST) -j RETURN
	
	$ipt_m -N PSW_OUTPUT
	$ipt_m -A PSW_OUTPUT $(dst $IPSET_LANIPLIST) -j RETURN
	$ipt_m -A PSW_OUTPUT $(dst $IPSET_VPSIPLIST) -j RETURN
	$ipt_m -A PSW_OUTPUT $(dst $IPSET_WHITELIST) -j RETURN

	ip rule add fwmark 1 lookup 100
	ip route add local 0.0.0.0/0 dev lo table 100
	
	# Load router's own proxy TCP
	if [ "$TCP_NODE" != "nil" ]; then
		local ipt_tmp=$ipt_n
		local dns_l="PSW_OUTPUT"
		local dns_r=$(REDIRECT $TCP_REDIR_PORT)
		local blist_r=$(REDIRECT $TCP_REDIR_PORT)
		local p_r=$(get_redirect_ipt $LOCALHOST_TCP_PROXY_MODE $TCP_REDIR_PORT)
		TCP_NODE_TYPE=$(echo $(config_n_get $TCP_NODE type) | tr 'A-Z' 'a-z')
		echolog "Load router's own proxy TCP ..."
		if [ "$TCP_NODE_TYPE" == "brook" ] && [ "$(config_n_get $TCP_NODE protocol client)" == "client" ]; then
			echolog "  - Enable TPROXY mode"
			ipt_tmp=$ipt_m
			dns_l="PSW"
			dns_r="$(REDIRECT $TCP_REDIR_PORT TPROXY)"
			blist_r=$(REDIRECT 1 MARK)
			p_r=$(get_redirect_ipt $LOCALHOST_TCP_PROXY_MODE 1 MARK)
		fi
		_proxy_tcp_access() {
			[ -n "${2}" ] || return 0
			ipset -q test $IPSET_LANIPLIST ${2}
			[ $? -eq 0 ] && {
				echolog "  - The upstream DNS server ${2} is already in the list of direct access. It is not mandatory to forward access to the server's TCP/${3} port to the TCP proxy"
				return 0
			}
			local ADD_INDEX=$FORCE_INDEX
			$ipt_tmp -I $dns_l $ADD_INDEX -p tcp -d ${2} --dport ${3} $dns_r
			[ "$ipt_tmp" == "$ipt_m" ] && $ipt_tmp -I PSW_OUTPUT $ADD_INDEX -p tcp -d ${2} --dport ${3} $(REDIRECT 1 MARK)
			echolog "  - [$?]Add the upstream DNS server ${2}:${3} to the TCP forwarding chain ${ADD_INDEX} of the router's own proxy"
		}
		[ "$use_tcp_node_resolve_dns" == 1 ] && hosts_foreach DNS_FORWARD _proxy_tcp_access 53
		$ipt_tmp -A OUTPUT -p tcp -j PSW_OUTPUT
		[ "$TCP_NO_REDIR_PORTS" != "disable" ] && {
			$ipt_tmp -A PSW_OUTPUT -p tcp -m multiport --dport $TCP_NO_REDIR_PORTS -j RETURN
			echolog "  - [$?]Do not proxy TCP ports: $TCP_NO_REDIR_PORTS"
		}
		$ipt_tmp -A PSW_OUTPUT -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_SHUNTLIST) $blist_r
		$ipt_tmp -A PSW_OUTPUT -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_BLACKLIST) $blist_r
		$ipt_tmp -A PSW_OUTPUT -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $p_r
	fi

	local PR_INDEX=$(RULE_LAST_INDEX "$ipt_n" PREROUTING ADBYBY)
	if [ "$PR_INDEX" == "0" ]; then
		PR_INDEX=$(RULE_LAST_INDEX "$ipt_n" PREROUTING prerouting_rule)
	else
		echolog "Found adbyby rule chain, adbyby rule takes precedence..."
	fi
	PR_INDEX=$((PR_INDEX + 1))
	$ipt_n -I PREROUTING $PR_INDEX -p tcp -j PSW
	echolog "Use linked list PREROUTING to arrange index${PR_INDEX}[$?]"
	
	$ip6t_n -N PSW
	$ip6t_n -A PREROUTING -j PSW
	$ip6t_n -N PSW_OUTPUT
	$ip6t_n -A OUTPUT -p tcp -j PSW_OUTPUT
	
	$ip6t_m -N PSW
	$ip6t_m -A PREROUTING -j PSW
	$ip6t_m -N PSW_OUTPUT
	$ip6t_m -A OUTPUT -p tcp -j PSW_OUTPUT
	[ -n "$lan_ifname" ] && {
		lan_ipv6=$(ip address show $lan_ifname | grep -w "inet6" | awk '{print $2}') #当前LAN IPv6段
		[ -n "$lan_ipv6" ] && {
			for ip in $lan_ipv6; do
				$ip6t_n -A PSW -d $ip -j RETURN
				$ip6t_n -A PSW_OUTPUT -d $ip -j RETURN
			done
		}
	}
	
	if [ "$PROXY_IPV6" == "1" ]; then
		local msg="IPv6 Improper configuration, unable to proxy"
		$ip6t_n -A PSW -p tcp $(REDIRECT $TCP_REDIR_PORT)
		$ip6t_n -A PSW_OUTPUT -p tcp $(REDIRECT $TCP_REDIR_PORT)
		msg="${msg}, Forward IPv6 TCP traffic to the node [$?]"
		echolog "$msg"
	fi

	# Filter Socks node
	[ "$SOCKS_ENABLED" = "1" ] && {
		local ids=$(uci show $CONFIG | grep "=socks" | awk -F '.' '{print $2}' | awk -F '=' '{print $1}')
		echolog "Analyze the nodes used by the Socks service..."
		local id enabled node port msg num
		for id in $ids; do
			enabled=$(config_n_get $id enabled 0)
			[ "$enabled" == "1" ] || continue
			node=$(config_n_get $id node nil)
			port=$(config_n_get $id port 0)
			msg="Socks service [:${port}]"
			if [ "$node" == "nil" ] || [ "$port" == "0" ]; then
				msg="${msg} Not configured completely, skip"
			elif [ "$(echo $node | grep ^tcp)" ]; then
				eval "node=\${TCP_NODE}"
				msg="${msg} Use the same node as the TCP proxy to automatically switch ${num}, postpone processing"
			else
				filter_node $node TCP > /dev/null 2>&1 &
				filter_node $node UDP > /dev/null 2>&1 &
			fi
			echolog "  - ${msg}"
		done
	}

	# Handling of shunts or dolls for rotating nodes
	local node port stream switch
	for stream in TCP UDP; do
		eval "node=\${${stream}_NODE}"
		eval "port=\${${stream}_REDIR_PORT}"
		echolog "Analyze $stream proxy automatic switch..."
		[ "$node" == "tcp" ] && [ "$stream" == "UDP" ] && {
			eval "node=\${TCP_NODE}"
			eval "port=\${TCP_REDIR_PORT}"
			echolog "  - Configuration using TCP proxy"
		}
		if [ "$node" != "nil" ]; then
			filter_node $node $stream $port > /dev/null 2>&1 &
		else
			echolog "  - Ignore invalid $stream proxy switch automatically"
		fi
	done
	
	# Load router's own proxy UDP
	if [ "$UDP_NODE" != "nil" ]; then
		echolog "Load router's own UDP proxy..."
		local UDP_NODE_TYPE=$(echo $(config_n_get $UDP_NODE type) | tr 'A-Z' 'a-z')
		local ADD_INDEX=$FORCE_INDEX
		_proxy_udp_access() {
			[ -n "${2}" ] || return 0
			ipset -q test $IPSET_LANIPLIST ${2}
			[ $? == 0 ] && {
				echolog "  - The upstream DNS server ${2} is already in the list of direct access. It is not mandatory to forward access to the server's UDP/${3} port to the UDP proxy"
				return 0
			}
			$ipt_m -I PSW $ADD_INDEX -p udp -d ${2} --dport ${3} $(REDIRECT $UDP_REDIR_PORT TPROXY)
			$ipt_m -I PSW_OUTPUT $ADD_INDEX -p udp -d ${2} --dport ${3} $(REDIRECT 1 MARK)
			echolog "  - [$?]Add the upstream DNS server ${2}:${3} to the router's own proxy UDP forwarding chain ${ADD_INDEX}"
		}
		[ "$use_udp_node_resolve_dns" == 1 ] && hosts_foreach DNS_FORWARD _proxy_udp_access 53
		$ipt_m -A OUTPUT -p udp -j PSW_OUTPUT
		[ "$UDP_NO_REDIR_PORTS" != "disable" ] && {
			$ipt_m -A PSW_OUTPUT -p udp -m multiport --dport $UDP_NO_REDIR_PORTS -j RETURN
			echolog "  - [$?]Do not proxy UDP port: $UDP_NO_REDIR_PORTS"
		}
		$ipt_m -A PSW_OUTPUT -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_SHUNTLIST) $(REDIRECT 1 MARK)
		$ipt_m -A PSW_OUTPUT -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_BLACKLIST) $(REDIRECT 1 MARK)
		$ipt_m -A PSW_OUTPUT -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(get_redirect_ipt $LOCALHOST_UDP_PROXY_MODE 1 MARK)
	fi
	
	$ipt_m -A PREROUTING -j PSW
	
	load_acl
	
	# dns_hijack "force"
	
	echolog "The firewall rules are loaded!"
}

del_firewall_rule() {
	ib_nat_exist=$($ipt_n -nL PREROUTING | grep -c PSW)
	if [ ! -z "$ib_nat_exist" ];then
		until [ "$ib_nat_exist" = 0 ]
	do
		$ipt_n -D PREROUTING -p tcp -j PSW 2>/dev/null
		$ipt_n -D OUTPUT -p tcp -j PSW_OUTPUT 2>/dev/null
		
		$ipt_m -D PREROUTING -j PSW 2>/dev/null
		$ipt_m -D OUTPUT -p tcp -j PSW_OUTPUT 2>/dev/null
		$ipt_m -D OUTPUT -p udp -j PSW_OUTPUT 2>/dev/null
		
		$ip6t_n -D PREROUTING -j PSW 2>/dev/null
		$ip6t_n -D OUTPUT -p tcp -j PSW_OUTPUT 2>/dev/null
		
		$ip6t_m -D PREROUTING -j PSW 2>/dev/null
		$ip6t_m -D OUTPUT -p tcp -j PSW_OUTPUT 2>/dev/null
		
		ib_nat_exist=$(expr $ib_nat_exist - 1)
	done
	fi
	$ipt_n -F PSW 2>/dev/null && $ipt_n -X PSW 2>/dev/null
	$ipt_n -F PSW_OUTPUT 2>/dev/null && $ipt_n -X PSW_OUTPUT 2>/dev/null
	$ipt_m -F PSW 2>/dev/null && $ipt_m -X PSW 2>/dev/null
	$ipt_m -F PSW_OUTPUT 2>/dev/null && $ipt_m -X PSW_OUTPUT 2>/dev/null
	$ip6t_n -F PSW 2>/dev/null && $ip6t_n -X PSW 2>/dev/null
	$ip6t_n -F PSW_OUTPUT 2>/dev/null && $ip6t_n -X PSW_OUTPUT 2>/dev/null
	$ip6t_m -F PSW 2>/dev/null && $ip6t_m -X PSW 2>/dev/null
	$ip6t_m -F PSW_OUTPUT 2>/dev/null && $ip6t_m -X PSW_OUTPUT 2>/dev/null
	
	ip rule del fwmark 1 lookup 100 2>/dev/null
	ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null

	ipset -F $IPSET_LANIPLIST >/dev/null 2>&1 && ipset -X $IPSET_LANIPLIST >/dev/null 2>&1 &
	ipset -F $IPSET_VPSIPLIST >/dev/null 2>&1 && ipset -X $IPSET_VPSIPLIST >/dev/null 2>&1 &
	#ipset -F $IPSET_SHUNTLIST >/dev/null 2>&1 && ipset -X $IPSET_SHUNTLIST >/dev/null 2>&1 &
	#ipset -F $IPSET_GFW >/dev/null 2>&1 && ipset -X $IPSET_GFW >/dev/null 2>&1 &
	#ipset -F $IPSET_GFW6 >/dev/null 2>&1 && ipset -X $IPSET_GFW6 >/dev/null 2>&1 &
	#ipset -F $IPSET_CHN >/dev/null 2>&1 && ipset -X $IPSET_CHN >/dev/null 2>&1 &
	#ipset -F $IPSET_CHN6 >/dev/null 2>&1 && ipset -X $IPSET_CHN6 >/dev/null 2>&1 &
	#ipset -F $IPSET_BLACKLIST >/dev/null 2>&1 && ipset -X $IPSET_BLACKLIST >/dev/null 2>&1 &
	#ipset -F $IPSET_BLACKLIST2 >/dev/null 2>&1 && ipset -X $IPSET_BLACKLIST2 >/dev/null 2>&1 &
	#ipset -F $IPSET_BLACKLIST3 >/dev/null 2>&1 && ipset -X $IPSET_BLACKLIST3 >/dev/null 2>&1 &
	ipset -F $IPSET_WHITELIST >/dev/null 2>&1 && ipset -X $IPSET_WHITELIST >/dev/null 2>&1 &
	echolog "The deletion of related firewall rules is complete."
}

flush_ipset() {
	ipset -F $IPSET_LANIPLIST >/dev/null 2>&1 && ipset -X $IPSET_LANIPLIST >/dev/null 2>&1 &
	ipset -F $IPSET_VPSIPLIST >/dev/null 2>&1 && ipset -X $IPSET_VPSIPLIST >/dev/null 2>&1 &
	ipset -F $IPSET_SHUNTLIST >/dev/null 2>&1 && ipset -X $IPSET_SHUNTLIST >/dev/null 2>&1 &
	ipset -F $IPSET_GFW >/dev/null 2>&1 && ipset -X $IPSET_GFW >/dev/null 2>&1 &
	#ipset -F $IPSET_GFW6 >/dev/null 2>&1 && ipset -X $IPSET_GFW6 >/dev/null 2>&1 &
	ipset -F $IPSET_CHN >/dev/null 2>&1 && ipset -X $IPSET_CHN >/dev/null 2>&1 &
	ipset -F $IPSET_CHN6 >/dev/null 2>&1 && ipset -X $IPSET_CHN6 >/dev/null 2>&1 &
	ipset -F $IPSET_BLACKLIST >/dev/null 2>&1 && ipset -X $IPSET_BLACKLIST >/dev/null 2>&1 &
	ipset -F $IPSET_BLACKLIST2 >/dev/null 2>&1 && ipset -X $IPSET_BLACKLIST2 >/dev/null 2>&1 &
	ipset -F $IPSET_BLACKLIST3 >/dev/null 2>&1 && ipset -X $IPSET_BLACKLIST3 >/dev/null 2>&1 &
	ipset -F $IPSET_WHITELIST >/dev/null 2>&1 && ipset -X $IPSET_WHITELIST >/dev/null 2>&1 &
}

flush_include() {
	echo '#!/bin/sh' >$FWI
}

gen_include() {
	flush_include
	cat <<-EOF >>$FWI
		/etc/init.d/passwall reload
	EOF
	return 0
}

start() {
	add_firewall_rule
	gen_include
}

stop() {
	del_firewall_rule
	flush_include
}

case $1 in
flush_ipset)
	flush_ipset
	;;
stop)
	stop
	;;
start)
	start
	;;
*) ;;
esac
