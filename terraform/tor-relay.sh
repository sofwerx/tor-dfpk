#!/bin/bash

export DEBIAN_FRONTEND=noninteractive

## Discover public and private IPv4 addresses for this instance
PUBLIC_IPV4="$(curl -qs http://169.254.169.254/latest/meta-data/public-ipv4)"
PRIVATE_IPV4="$(curl -qs http://169.254.169.254/latest/meta-data/local-ipv4)"

mac=$(curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/ | head -1 | cut -d/ -f1)
PUBLIC_IPV6=$(curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/$mac/ipv6s | head -1 | cut -d: -f1-4)

echo "iface eth0 inet6 dhcp" > /etc/network/interfaces.d/60-default-with-ipv6.cfg
sudo dhclient -6

## Install some extra things
sudo apt-get update
export DEBIAN_FRONTEND=noninteractive
sudo -E apt-get install -y fail2ban dnsmasq

# Deal with AWS split-horizon DNS and using both IPV4 and IPV6 DNS servers

# Disable resolvconf updates, because we can't have nice things.
resolvconf --disable-updates

mkdir -p /var/run/dnsmasq/
if [ ! -f /var/run/dnsmasq/resolv.conf ] ; then
  cp /etc/resolv.conf /var/run/dnsmasq/resolv.conf
fi

domains="$(grep domain-name /var/lib/dhcp/dhclient.eth0.leases | awk '{print $3}' | cut -d';' -f1 | grep '"' | cut -d'"' -f2)"
servers="$(grep domain-name-server /var/lib/dhcp/dhclient.eth0.leases | awk '{print $3}' | cut -d';' -f1)"

cat <<EOC > /etc/dnsmasq.conf
interface=*
port=53
bind-interfaces
user=dnsmasq
group=nogroup
resolv-file=/var/run/dnsmasq/resolv.conf
pid-file=/var/run/dnsmasq/dnsmasq.pid
domain-needed
all-servers
EOC

## Make sure we handle split-horizon for both ec2.internal and amazonaws.com
for domain in $domains amazonaws.com ; do
  # Route ec2.internal to AWS servers by default
  for server in $servers; do
    echo 'server=/'"$domain"'/'"$server" >> /etc/dnsmasq.conf
  done
done

# Route all other queries, simultaneously, to both ipv4 and ipv6 DNS servers at Google
for server in 8.8.8.8 8.8.4.4 2001:4860:4860::8888 2001:4860:4860::8844 ; do
  echo 'server=/*/'"$server" >> /etc/dnsmasq.conf
done

cat <<EOR > /etc/resolv.conf
search $domains
nameserver $PRIVATE_IPV4
EOR

/etc/init.d/dnsmasq restart

export USER_NAME=${USER_NAME:-ubuntu}
export USER_HOME=${USER_HOME:-/home/ubuntu}
# Add ssh key trusts for manager user
mkdir -p ${USER_HOME}/.ssh
chown ${USER_NAME}.${USER_NAME} ${USER_HOME}/.ssh
chmod 700 ${USER_HOME}/.ssh
AUTHORIZED_KEYS_FILE=$(mktemp /tmp/authorized_keys.XXXXXXXX)
(
  if [ -f /home/admin/.ssh/authorized_keys ] ; then cat /home/admin/.ssh/authorized_keys ; fi
  if [ -f /home/${USER_NAME}/.ssh/authorized_keys ] ; then cat /home/${USER_NAME}/.ssh/authorized_keys ; fi
  curl -sL https://github.com/ianblenke.keys
  curl -sL https://github.com/tabinfl.keys
  curl -sL https://github.com/ahernmikej.keys
  curl -sL https://github.com/camswx.keys
  curl -sL https://github.com/Shad0wSt4R.keys
) | sort | uniq > ${AUTHORIZED_KEYS_FILE}
mv ${AUTHORIZED_KEYS_FILE} ${USER_HOME}/.ssh/authorized_keys
chown ${USER_NAME}.${USER_NAME} ${USER_HOME}/.ssh/authorized_keys
chmod 600 ${USER_HOME}/.ssh/authorized_keys

# Update and install Tor
apt-get update 
DEBIAN_FRONTEND=noninteractive apt-get install -y  apt-transport-https
cat <<EOF > /etc/apt/sources.list.d/tor.list
deb https://deb.torproject.org/torproject.org bionic main
deb-src https://deb.torproject.org/torproject.org bionic main
EOF
apt-key adv --recv-keys --keyserver keys.gnupg.net  74A941BA219EC810
apt-get update 
DEBIAN_FRONTEND=noninteractive apt-get install -y tor deb.torproject.org-keyring


# This is what is there by default
cat <<EOF > /usr/share/tor/tor-service-defaults-torrc
DataDirectory /var/lib/tor
PidFile /var/run/tor/tor.pid
RunAsDaemon 1
User debian-tor

ControlSocket /var/run/tor/control GroupWritable RelaxDirModeCheck
ControlSocketsGroupWritable 1
SocksPort unix:/var/run/tor/socks WorldWritable
SocksPort 9050

CookieAuthentication 1
CookieAuthFileGroupReadable 1
CookieAuthFile /var/run/tor/control.authcookie

Log notice syslog
EOF

# The /etc/tor/torrc is entirely commented out by default. Best not touch that.

# We should be putting our own scripts into /etc/torrc.d/ rather than updating the above "here documents".
cat <<EOF > /etc/torrc.d/relay.sh
# Run Tor as a regular user (do not change this)
#User debian-tor

TestingTorNetwork 1

## Comprehensive Bootstrap Testing Options ##
# These typically launch a working minimal Tor network in 25s-30s,
# and a working HS Tor network in 40-45s.
# See authority.tmpl for a partial explanation
#AssumeReachable 0
#Default PathsNeededToBuildCircuits 0.6
#Disable TestingDirAuthVoteExit
#Disable TestingDirAuthVoteHSDir
#Default V3AuthNIntervalsValid 3

## Rapid Bootstrap Testing Options ##
# These typically launch a working minimal Tor network in 6s-10s
# These parameters make tor networks bootstrap fast,
# but can cause consensus instability and network unreliability
# (Some are also bad for security.)
AssumeReachable 1
PathsNeededToBuildCircuits 0.25
TestingDirAuthVoteExit *
TestingDirAuthVoteHSDir *
V3AuthNIntervalsValid 2

## Always On Testing Options ##
# We enable TestingDirAuthVoteGuard to avoid Guard stability requirements
TestingDirAuthVoteGuard *
# We set TestingMinExitFlagThreshold to 0 to avoid Exit bandwidth requirements
TestingMinExitFlagThreshold 0
# VoteOnHidServDirectoriesV2 needs to be set for HSDirs to get the HSDir flag
#Default VoteOnHidServDirectoriesV2 1

## Options that we always want to test ##
Sandbox 1

# Private tor network configuration
RunAsDaemon 0
ConnLimit 60
ShutdownWaitLength 0
#PidFile /var/lib/tor/pid
Log info stdout
ProtocolWarnings 1
SafeLogging 0
DisableDebuggerAttachment 0

#DirPortFrontPage /usr/share/doc/tor/tor-exit-notice.html
EOF

systemctl restart tor

