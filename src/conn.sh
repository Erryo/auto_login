#!/bin/bash

auth_serv_url="10.80.0.1:8000/api/captiveportal/access/logon/0/"
headers="Content-Type: application/x-www-form-urlencoded"
params='user=trifanma&password=Nonameorpass1' # use single quotes

SECONDS=0
duration=0

wait_long() {
  if [[ $((SECONDS - duration)) -lt $((84 * 60)) ]]; then
    sleep $((88 * 60)) # sleep half hour to not overping server
    return
  fi

  sleep $((1 * 60))
  return
}

wait_dumb() {
  sleep $((1 * 60))
}

recon() {
  echo "Testing internet availability"$(date) >>~/dev/auto_conn.log
  ping_result=$(ping -qc1 8.8.8.8 2>&1 | awk -F'/' 'END{ print (/^rtt/? "OK":"FAIL") }')

  if [[ $ping_result = "OK" ]]; then
    echo "Internet available"$(date) >>~/dev/auto_conn.log
    wait_dumb
    return
  fi

  echo "Internet not available"$(date) >>~/dev/auto_conn.log
  echo "Sending cURl" $(date)
  #    curl -X POST 10.80.0.1:8000/api/captiveportal/access/logon/0/ -H 'Content-Type: application/x-www-form-urlencoded'  --data 'user=trifanma&password=Nonameorpass1'
  curl -X POST "$auth_serv_url" -H "$headers" --data "$params"

  sleep 10

  ping_result=$(ping -qc1 8.8.8.8 2>&1 | awk -F'/' 'END{ print (/^rtt/? "OK":"FAIL") }')
  if [[ $ping_result = "OK" ]]; then
    echo "Succesfully logged in" $(date) >>~/dev/auto_conn.log
    duration=$SECONDS
    return
  else
    echo "Trying again" $(date) >>~/dev/auto_conn.log
    curl -X POST "$auth_serv_url" -H "$headers" --data "$params"
    return
  fi
}

while [[ true ]]; do
  ssid=$(iwgetid -r) # cli tool to get ssid

  if [[ $ssid = 'ohg' ]]; then
    echo "Connected to:" $ssid $(date) >>~/dev/auto_conn.log
    recon
  else
    echo "not connected" $ssid $(date) >>~/dev/auto_conn.log
    sleep 60
  fi
done
