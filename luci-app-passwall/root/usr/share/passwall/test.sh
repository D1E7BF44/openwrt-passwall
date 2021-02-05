#!/bin/sh

CONFIG=passwall
LOG_FILE=/var/log/$CONFIG.log

echolog() {
	local d="$(date "+%Y-%m-%d %H:%M:%S")"
	#echo -e "$d: $1"
	echo -e "$d: $1" >> $LOG_FILE
}

config_n_get() {
	local ret=$(uci -q get "${CONFIG}.${1}.${2}" 2>/dev/null)
	echo "${ret:=$3}"
}

config_t_get() {
	local index=0
	[ -n "$4" ] && index=$4
	local ret=$(uci -q get $CONFIG.@$1[$index].$2 2>/dev/null)
	echo ${ret:=$3}
}

test_url() {
	local url=$1
	local try=1
	[ -n "$2" ] && try=$2
	local timeout=2
	[ -n "$3" ] && timeout=$3
	local extra_params=$4
	status=$(/usr/bin/curl -I -o /dev/null -skL $extra_params --connect-timeout $timeout --retry $try -w %{http_code} "$url")
	case "$status" in
		204|\
		200)
			status=200
		;;
	esac
	echo $status
}

test_proxy() {
	local try=3
	result=0
	status=$(test_url "https://www.google.com/generate_204" $try)
	if [ "$status" = "200" ]; then
		result=0
	else
		status2=$(test_url "https://www.baidu.com" $try)
		if [ "$status2" = "200" ]; then
			result=1
		else
			result=2
		fi
	fi
	echo $result
}

test_auto_switch() {
	local type=$1
	local b_tcp_nodes=$3
	local now_node
	if [ -f "/var/etc/$CONFIG/id/${type}" ]; then
		now_node=$(cat /var/etc/$CONFIG/id/${type})
	else
		return 1
	fi

	status=$(test_proxy)
	if [ "$status" == 2 ]; then
		echolog "Automatic switching detection: unable to connect to the network, please check whether the network is normal!"
		return 2
	fi
	
	local restore_switch=$(config_t_get auto_switch restore_switch 0)
	if [ "$restore_switch" == "1" ]; then
		#Check whether the master node can be used
		local main_node=$(config_t_get auto_switch tcp_main)
		if [ "$now_node" != "$main_node" ]; then
			local node_type=$(echo $(config_n_get $main_node type) | tr 'A-Z' 'a-z')
			if [ "$node_type" == "socks" ]; then
				local node_address=$(config_n_get $main_node address)
				local node_port=$(config_n_get $main_node port)
				[ -n "$node_address" ] && [ -n "$node_port" ] && local curlx="socks5h://$node_address:$node_port"
			else
				local tmp_port=$(/usr/share/passwall/app.sh get_new_port 61080 tcp)
				/usr/share/passwall/app.sh run_socks "$main_node" "127.0.0.1" "$tmp_port" "/var/etc/passwall/auto_switch.json" "10"
				local curlx="socks5h://127.0.0.1:$tmp_port"
			fi
			sleep 10s
			proxy_status=$(test_url "https://www.google.com/generate_204" 3 3 "-x $curlx")
			ps -w | grep -v "grep" | grep "/var/etc/passwall/auto_switch.json" | awk '{print $1}' | xargs kill -9 >/dev/null 2>&1
			if [ "$proxy_status" -eq 200 ]; then
				#The main node is normal, switch to the main node
				echolog "Automatic switching detection: ${type} master node is normal, switch to the master node! "
				/usr/share/passwall/app.sh node_switch $type $2 $main_node
				return 0
			fi
		fi
	fi
	
	if [ "$status" == 0 ]; then
		echolog "Automatic switching detection: ${type} node $(config_n_get $now_node type) $(config_n_get $now_node address) $(config_n_get $now_node port)正常。"
		return 0
	elif [ "$status" == 1 ]; then
		echolog "Automatic switching detection: ${type} node is abnormal, start switching nodes! "
		local new_node
		in_backup_nodes=$(echo $b_tcp_nodes | grep $now_node)
		#Determine whether the current node exists in the standby node list
		if [ -z "$in_backup_nodes" ]; then
			# If it does not exist, set the first node as a new node
			new_node=$(echo $b_tcp_nodes | awk -F ' ' '{print $1}')
		else
			# If it exists, set the next standby node as the new node
			#local count=$(expr $(echo $b_tcp_nodes | grep -o ' ' | wc -l) + 1)
			local next_node=$(echo $b_tcp_nodes | awk -F "$now_node" '{print $2}' | awk -F " " '{print $1}')
			if [ -z "$next_node" ]; then
				new_node=$(echo $b_tcp_nodes | awk -F ' ' '{print $1}')
			else
				new_node=$next_node
			fi
		fi
		/usr/share/passwall/app.sh node_switch $type $2 $new_node
		sleep 10s
		# After switching the node, wait 10 seconds and then check again, if it still fails, continue to switch until it is available
		status2=$(test_proxy)
		if [ "$status2" -eq 0 ]; then
			echolog "Automatic switching detection: ${type} node switching is complete!"
			return 0
		elif [ "$status2" -eq 1 ]; then
			test_auto_switch $1 $2 "$3"
		elif [ "$status2" -eq 2 ]; then
			return 2
		fi
	fi
}

start() {
	ENABLED=$(config_t_get global enabled 0)
	[ "$ENABLED" != 1 ] && _return 1
	ENABLED=$(config_t_get auto_switch enable 0)
	[ "$ENABLED" != 1 ] && _return 1
	delay=$(config_t_get auto_switch testing_time 1)
	sleep ${delay}m
	while [ "$ENABLED" -eq 1 ]
	do
		TCP_NODE=$(config_t_get auto_switch tcp_node nil)
		[ -n "$TCP_NODE" -a "$TCP_NODE" != "nil" ] && {
			test_auto_switch TCP tcp "$TCP_NODE"
		}
		delay=$(config_t_get auto_switch testing_time 1)
		sleep ${delay}m
	done
}

case $1 in
test_url)
	test_url $2
	;;
*)
	start
	;;
esac
