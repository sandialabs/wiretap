#!/bin/bash

filename="wt-tests.md"
client_container="wiretap-client-1"
server_container="wiretap-server-1"
target_container="wiretap-target-1"

if [[ ! -f "$filename" ]]; then
    echo "'$filename' not found"
    exit 1
fi

function doClient() {
    echo "[C] $1"
    bg=""
    if [[ "${1: -1}" == "&" ]]; then
        bg="-d"
        # Remove the trailing '&' for the command execution
        cmd="${1:0:-1}"
        echo "[C BG] $cmd"
    else
        cmd="$1"
    fi
    docker exec $bg "$client_container" bash -c "$cmd"
}

function doServer() {
    echo "[S] $1"
    bg=""
    if [[ "${1: -1}" == "&" ]]; then
        bg="-d"
        # Remove the trailing '&' for the command execution
        cmd="${1:0:-1}"
        echo "[S BG] $cmd"
    else
        cmd="$1"
    fi
    docker exec $bg "$server_container" bash -c "$cmd"
}

function doTarget() {
    echo "[T] $1"
    bg=""
    if [[ "${1: -1}" == "&" ]]; then
        bg="-d"
        # Remove the trailing '&' for the command execution
        cmd="${1:0:-1}"
        echo "[T BG] $cmd"
    else
        cmd="$1"
    fi
    
    docker exec $bg "$target_container" bash -c "$cmd"
}

function copyToServer() {
    local src="$1"
    local dest="$2"
    docker cp "$client_container":"$src" /tmp/wt.tmp
    #docker cp /tmp/wt.tmp "$server_container":"$dest"
    docker cp /tmp/wt.tmp "$server_container":"$src"
    rm /tmp/wt.tmp
}

function copyToTarget() {
    local src="$1"
    local dest="$2"
    docker cp "$client_container":"$src" /tmp/wt.tmp
    docker cp /tmp/wt.tmp "$target_container":"$src"
    rm /tmp/wt.tmp
}

running=0

while IFS= read -r line
do
    if [[ "$line" == '#'* ]]; then
        echo "$line"
        continue
    fi

    if [[ "$line" == '```'* ]]; then
        #echo "Line starts with three backticks"
        if [[ $running -eq 1 ]]; then
            echo "End test"
            echo
            echo
            running=0
            continue
        fi

        running=1
        echo "Starting a new test"
        continue
    fi

    if [[ $running -eq 1 ]]; then

        if [[ "$line" == 'COPYCONF'* ]]; then
            mapfile -t conf_list < <(docker exec "$client_container" bash -c 'find /wiretap -type f -name "wiretap_server*.conf"')
            for conf in "${conf_list[@]}"; do
                copyToServer $conf /wiretap/
                copyToTarget $conf /wiretap/
            done
            
            continue
        fi

        if [[ "$line" == 'WAIT'* ]]; then
            wait_arg=$(echo "$line" | awk '{print $2}')
            echo "Waiting for $wait_arg seconds..."
            sleep "$wait_arg"
            continue
        fi

        if [[ "$line" == 'EXIT'* ]]; then
            exit 0
        fi

        cmd="${line:1}"
        if [[ "$line" == '!'* ]]; then
            doClient "$cmd"
            sleep 0.5

        elif [[ "$line" == '@'* ]]; then
            doServer "$cmd"
            sleep 0.5

        elif [[ "$line" == '%'* ]]; then
            doTarget "$cmd"
            sleep 0.5
        fi
    fi

done < "$filename"