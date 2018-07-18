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
mkdir -p /etc/torrc.d

# We should be putting our own scripts into /etc/torrc.d/ rather than updating the above "here documents".
cat <<EOF > /etc/torrc.d/bridge.sh
AuthoritativeDirectory 1
V3AuthoritativeDirectory 1

# Speed up the consensus cycle as fast as it will go
# Voting Interval can be:
#   10, 12, 15, 18, 20, 24, 25, 30, 36, 40, 45, 50, 60, ...
# Testing Initial Voting Interval can be:
#    5,  6,  8,  9, or any of the possible values for Voting Interval,
# as they both need to evenly divide 30 minutes.
# If clock desynchronisation is an issue, use an interval of at least:
#   18 * drift in seconds, to allow for a clock slop factor
TestingV3AuthInitialVotingInterval 300
#V3AuthVotingInterval 15
# VoteDelay + DistDelay must be less than VotingInterval
TestingV3AuthInitialVoteDelay 5
V3AuthVoteDelay 5
TestingV3AuthInitialDistDelay 5
V3AuthDistDelay 5
# This is autoconfigured by chutney, so you probably don't want to use it
#TestingV3AuthVotingStartOffset 0

# Work around situations where the Exit, Guard and HSDir flags aren't being set
# These flags are all set eventually, but it takes Guard up to ~30 minutes
# We could be more precise here, but it's easiest just to vote everything
# Clients are sensible enough to filter out Exits without any exit ports,
# and Guards and HSDirs without ORPorts
# If your tor doesn't recognise TestingDirAuthVoteExit/HSDir,
# either update your chutney to a 2015 version,
# or update your tor to a later version, most likely 0.2.6.2-final

# These are all set in common.i in the Comprehensive/Rapid sections
# Work around Exit requirements
#TestingDirAuthVoteExit *
# Work around bandwidth thresholds for exits
#TestingMinExitFlagThreshold 0
# Work around Guard uptime requirements
#TestingDirAuthVoteGuard *
# Work around HSDir uptime and ORPort connectivity requirements
#TestingDirAuthVoteHSDir *
EOF

systemctl restart tor

