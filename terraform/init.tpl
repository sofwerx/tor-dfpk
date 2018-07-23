#!/bin/bash

for da_host in $(echo "${da_hosts}" | sed -e 's/,/ /') ; do
  echo $da_host
done > /etc/tor/da_hosts

echo "${bridge_hosts}" > /etc/tor/bridge_hosts
hostnamectl set-hostname "${hostname}"
