#!/bin/bash

(
export DEBIAN_FRONTEND=noninteractive

# Update the package index
apt-get update

# Force an ntp sync
apt-get install -y ntpdate
ntpdate pool.ntp.org

# Install ntp service to keep this instance on time
apt-get install -y ntp

# Install git and other setup dependencies
apt-get install -y git

# These variables are filled in by the terraform templater at render time
mkdir -p /etc/tor
echo "${da_hosts}" > /etc/tor/da_hosts
echo "${bridge_hosts}" > /etc/tor/bridge_hosts
hostnamectl set-hostname "${hostname}"
sed -e "s/localhost$/localhost $(hostname)/" -i /etc/hosts

TOR_ORPORT=${tor_orport}
TOR_DAPORT=${tor_daport}
TOR_DIR=/etc/tor
TOR_HS_PORT=80
TOR_HS_ADDR=127.0.0.1

export TOR_NICK=${role}${index}
echo "Setting Nickname: $TOR_NICK"
echo -e "\nNickname $TOR_NICK" > /etc/torrc.d/nickname

## Discover public and private IPv4 addresses for this instance
PUBLIC_IPV4="$(curl -qs http://169.254.169.254/latest/meta-data/public-ipv4)"
PRIVATE_IPV4="$(curl -qs http://169.254.169.254/latest/meta-data/local-ipv4)"

mac=$(curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/ | head -1 | cut -d/ -f1)
PUBLIC_IPV6=$(curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/$mac/ipv6s | head -1 | cut -d: -f1-4)

mkdir -p /etc/network/interfaces.d
echo "iface eth0 inet6 dhcp" > /etc/network/interfaces.d/60-default-with-ipv6.cfg
sudo dhclient -6

## Install some extra things
sudo apt-get update
export DEBIAN_FRONTEND=noninteractive
sudo -E apt-get install -y fail2ban dnsmasq curl

# Deal with AWS split-horizon DNS and using both IPV4 and IPV6 DNS servers

# Disable resolvconf updates, because we can't have nice things.
which resolveconf && resolvconf --disable-updates

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

export USER_NAME=ubuntu
export USER_HOME=/home/ubuntu
# Add ssh key trusts for manager user
mkdir -p $USER_HOME/.ssh
chown $USER_NAME.$USER_NAME $USER_HOME/.ssh
chmod 700 $USER_HOME/.ssh
AUTHORIZED_KEYS_FILE=$(mktemp /tmp/authorized_keys.XXXXXXXX)
(
  if [ -f /home/admin/.ssh/authorized_keys ] ; then cat /home/admin/.ssh/authorized_keys ; fi
  if [ -f /home/$USER_NAME/.ssh/authorized_keys ] ; then cat /home/$USER_NAME/.ssh/authorized_keys ; fi
  curl -sL https://github.com/ianblenke.keys
  curl -sL https://github.com/tabinfl.keys
  curl -sL https://github.com/ahernmikej.keys
  curl -sL https://github.com/camswx.keys
  curl -sL https://github.com/Shad0wSt4R.keys
) | sort | uniq > $AUTHORIZED_KEYS_FILE
mv $AUTHORIZED_KEYS_FILE $USER_HOME/.ssh/authorized_keys
chown $USER_NAME.$USER_NAME $USER_HOME/.ssh/authorized_keys
chmod 600 $USER_HOME/.ssh/authorized_keys

# Update and install Tor
apt-get update 
DEBIAN_FRONTEND=noninteractive apt-get install -y  apt-transport-https
cat <<EOF > /etc/apt/sources.list.d/tor.list
deb https://deb.torproject.org/torproject.org bionic main
deb-src https://deb.torproject.org/torproject.org bionic main
EOF
apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 74A941BA219EC810 || \
apt-key adv --keyserver keys.gnupg.net --recv-keys 74A941BA219EC810
apt-get update 
DEBIAN_FRONTEND=noninteractive apt-get install -y tor obfsproxy obfs4proxy deb.torproject.org-keyring

# Install aws cli tool
apt-get install -y python-pip
pip install awscli

# Sync down shared s3 bucket tor config tree
aws s3 sync s3://${s3_bucket}$TOR_DIR $TOR_DIR/

mkdir -p $TOR_DIR/$TOR_NICK
chmod 755 $TOR_DIR/$TOR_NICK

# Extract or package up the ssh host keys for ssh known_hosts sanity later
if [ -f $TOR_DIR/$TOR_NICK/ssh.tar.bz2 ] ; then
  tar xjf $TOR_DIR/$TOR_NICK/ssh.tar.bz2 -C /etc/ssh .
  systemctl restart ssh
else
  tar cjf $TOR_DIR/$TOR_NICK/ssh.tar.bz2 -C /etc/ssh .
fi

# This is the tor defaults file that we want to remain untouched
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
# That file includes files in the /etc/torrc.d directory tree, so let's use that instead.
# In order to do this we must specify where our directory is in the torrc.
if ! grep -e '^%include /etc/torrc.d/' /etc/tor/torrc > /dev/null 2>&1 ; then
  echo -e "%include /etc/torrc.d/" >> /etc/tor/torrc
  echo -e "Log notice file /var/log/tor/notices.log" >> /etc/tor/torrc
fi

mkdir -p /etc/torrc.d

# This is our base config shared by all nodes

cat <<EOF > /etc/torrc.d/base
# Run Tor as a regular user (do not change this)
#User debian-tor

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
#PathsNeededToBuildCircuits 0.25
#TestingDirAuthVoteExit *
#TestingDirAuthVoteHSDir *
#V3AuthNIntervalsValid 2

## Always On Testing Options ##
# We enable TestingDirAuthVoteGuard to avoid Guard stability requirements
TestingDirAuthVoteGuard *
# We set TestingMinExitFlagThreshold to 0 to avoid Exit bandwidth requirements
TestingMinExitFlagThreshold 0
# VoteOnHidServDirectoriesV2 needs to be set for HSDirs to get the HSDir flag
#Default VoteOnHidServDirectoriesV2 1

## Options that we always want to test ##
#Sandbox 1

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

echo -e "DataDirectory $TOR_DIR/$TOR_NICK" > /etc/torrc.d/datadirectory

TOR_IP=${ip}
if [ -z "$TOR_IP" ] ; then
  TOR_IP=$PUBLIC_IPV4
fi
echo "Address $TOR_IP" > /etc/torrc.d/address

#echo -e "ControlPort 0.0.0.0:9051" > /etc/torrc.d/controlport
#if [  -z "$TOR_CONTROL_PWD" ]; then
#  TOR_CONTROL_PWD="16:6971539E06A0F94C6011414768D85A25949AE1E201BDFE10B27F3B3EBA"
#fi
#echo -e "HashedControlPassword $TOR_CONTROL_PWD" > /etc/torrc.d/hashedcontrolpassword

# Each role has a set of differences
case ${role} in
  DA)
    mkdir -p $TOR_DIR/$TOR_NICK/hidden
    chmod 700 $TOR_DIR/$TOR_NICK/hidden

    cat <<EOF > /etc/torrc.d/da
TestingTorNetwork 1
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
#TestingV3AuthInitialVotingInterval 300
V3AuthVotingInterval 30
# VoteDelay + DistDelay must be less than VotingInterval
#TestingV3AuthInitialVoteDelay 5
V3AuthVoteDelay 5
#TestingV3AuthInitialDistDelay 5
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

HiddenServiceDir $TOR_DIR/$TOR_NICK/hidden
HiddenServicePort 80 localhost:8080
EOF

    echo -e "OrPort $TOR_ORPORT" > /etc/torrc.d/orport
    echo -e "Dirport $TOR_DAPORT" > /etc/torrc.d/daport
    echo -e "ExitPolicy reject *:*" > /etc/torrc.d/exitpolicy

    # TODO: Deal with securely handling the identity key
    KEYPATH=$TOR_DIR/$TOR_NICK/keys
    if ! [ -e $KEYPATH/authority_identity_key ] || \
       ! [ -e $KEYPATH/authority_signing_key ] || \
       ! [ -e $KEYPATH/authority_certificate ]
    then
    	mkdir -p $KEYPATH
    	echo "password" | tor-gencert --create-identity-key -m 12 -a $TOR_IP:$TOR_DAPORT \
            -i $KEYPATH/authority_identity_key \
            -s $KEYPATH/authority_signing_key \
            -c $KEYPATH/authority_certificate \
	    --passphrase-fd 0
    	tor --list-fingerprint --orport 1 \
    	    --dirserver "x 127.0.0.1:1 ffffffffffffffffffffffffffffffffffffffff" \
	    --datadirectory $TOR_DIR/$TOR_NICK
    	echo "Saving DA fingerprint to shared path"
    fi

    sed -i -e 's/^dir-address .*$/dir-address '$TOR_IP':'$TOR_DAPORT'/' $KEYPATH/authority_certificate

    # Prepare the REST server
    git clone -b add_rest_server https://github.com/sofwerx/tor-dfpk /tor-dfpk
    pushd /tor-dfpk/tor_auth_server
    cat <<EOF > /tor-dfpk/tor_auth_server/torconfig.json
{
    "DirAuthorities": [
EOF
    pushd /etc/torrc.d
    first=
    for da in DA* ; do
      if [ -n "$first" ]; then
        echo '    },{' >> /tor-dfpk/tor_auth_server/torconfig.json
      else
        echo '    {' >> /tor-dfpk/tor_auth_server/torconfig.json
      fi
      cat <<EOF >> /tor-dfpk/tor_auth_server/torconfig.json
            "nickname": "$da",
            "orport": $(cut -d' ' -f2 orport),
            "v3ident" : "$(grep -i v3ident $da | sed -e 's/^.*v3ident=//' | cut -d' ' -f1)",
            "flags": "no-v2",
            "ip": "$(cut -d' ' -f2 address)",
            "port": $(cut -d' ' -f2 daport),
            "fingerprint": "$(cut -d: -f2 DA1 | cut -d' ' -f2)"
EOF
      first=false
    done
    popd
    echo '    }' >> /tor-dfpk/tor_auth_server/torconfig.json
    cat <<EOF >> /tor-dfpk/tor_auth_server/torconfig.json
    ],
    "SocksPort": "0.0.0.0:9050",
    "UseBridges" : 1,
    "ClientTransportPlugin": {
        "transport": "obfs3",
        "binary": "/usr/bin/obfsproxy",
        "options": "--managed"
    },
    "Bridge": {
        "transport": "obfs3",
EOF
    echo '        "ip": "'$(cat /etc/tor/bridge_hosts)'","' >> /tor-dfpk/tor_auth_server/torconfig.json
    cat <<EOF >> /tor-dfpk/tor_auth_server/torconfig.json
        "orport": 443
    }
}
EOF
    cat /tor-dfpk/tor_auth_server/torconfig.json

    cat <<EOF > /etc/systemd/system/tor_auth_service.service
[Unit]
Description=Private TOR config auth service
After=syslog.target

[Service]
Type=simple
User=daemon
Group=daemon
WorkingDirectory=/tor-dfpk/tor_auth_server
ExecStart=/tor-dfpk/tor_auth_server/server.py
StandardOutput=syslog
StandardError=syslog

[Install]
WantedBy=multi-user.target
EOF
    cat /etc/systemd/system/tor_auth_service.service
    systemctl daemon-reload
    systemctl enable tor_auth_service
    systemctl start tor_auth_service
    popd

    ;;

  RELAY)
    echo "Setting role to RELAY"
    echo -e "SocksPort 0" > /etc/torrc.d/socksport
    echo -e "OrPort $TOR_ORPORT" > /etc/torrc.d/orport
    echo -e "ExitPolicy reject *:*" > /etc/tor/torrc.d/exitpolicy
    ;;

  BRIDGE)
    echo "Setting role to BRIDGE"
    echo -e "SocksPort 0" > /etc/torrc.d/socksport
    echo -e "BridgeRelay 1" > /etc/torrc.d/bridgerelay
    echo -e "OrPort 443" > /etc/torrc.d/orport
    echo -e "ExitPolicy reject *:*" > /etc/torrc.d/exitpolicy
    echo -e "ServerTransportPlugin obfs3,scramblesuit exec /usr/bin/obfsproxy managed" > /etc/torrc.d/servertransportplugin
    ## This is commented out as it requires obfs4proxy, which is not available in openwrt yet
    #echo -e "ServerTransportPlugin obfs4 exec /usr/bin/obfs4proxy managed" >> /etc/torrc.d/servertransportplugin
    echo "Waiting for other DA's to come up..."
    ;;

  EXIT)
    echo "Setting role to EXIT"
    echo -e "SocksPort 0" > /etc/torrc.d/orport
    echo -e "OrPort $TOR_ORPORT" > /etc/torrc.d/orport
    echo -e "ExitPolicy accept *:*" > /etc/torrc.d/exitpolicy
    echo "Waiting for other DA's to come up..."
    ;;

  CLIENT)
    echo "Setting role to CLIENT"
    echo -e "SOCKSPort 0.0.0.0:9050" > /etc/torrc.d/socksport
    ;;
  HS)
    # NOTE By default the HS role will point to a service running on port 80
    #  but there is no service running on port 80. You can either attach to 
    #  the container and start one, or better yet, point to another docker
    #  container on the network by setting the TOR_HS_ADDR to its IP
    echo "Setting role to HIDDENSERVICE"
    echo -e "HiddenServiceDir $TOR_DIR/$TOR_NICKNAME/hs" > /etc/torrc.d/hiddenservicedir
    echo -e "HiddenServicePort $TOR_HS_PORT $TOR_HS_ADDR\:$TOR_HS_PORT" > /etc/torrc.d/hiddenserviceport
    ;;
  *)
    echo "Role variable missing"
    exit 1
    ;;
esac

# Define the DAs on _every_ node
ls -1d $TOR_DIR/DA* | while read DA_DIR ; do
  TOR_NICK=$(basename $DA_DIR)
  AUTH=$(grep "fingerprint" $TOR_DIR/$TOR_NICK/keys/* | awk -F " " '{print $2}')
  NICK=$(cat $TOR_DIR/$TOR_NICK/fingerprint| awk -F " " '{print $1}')
  RELAY=$(cat $TOR_DIR/$TOR_NICK/fingerprint|awk -F " " '{print $2}')
  SERVICE=$(grep "dir-address" $TOR_DIR/$TOR_NICK/keys/* | awk -F " " '{print $2}')
  TORRC="DirAuthority $TOR_NICK orport=$TOR_ORPORT no-v2 v3ident=$AUTH $SERVICE  $RELAY"
  echo $TORRC > /etc/torrc.d/$TOR_NICK
done

# Generate the torrc file that a client would use to connect
(
  cat /etc/torrc.d/DA*
  cat <<EOF
SOCKSPort 0.0.0.0:9050
UseBridges 1
ClientTransportPlugin obfs3,scramblesuit exec /usr/bin/obfsproxy --managed
## This is commented out as it requires obfs4proxy, which is not available in openwrt yet
#ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy --managed
EOF
  BRIDGE_NUMBER=0
  for BRIDGE_HOST in $(echo "${bridge_hosts}" | sed -e 's/,/ /g'); do
    BRIDGEDIR="/etc/tor/BRIDGE$BRIDGE_NUMBER"
    ((BRIDGE_NUMBER++))
    fingerprint="$(cat $BRIDGEDIR/fingerprint | cut -d' ' -f2)"
    echo "Bridge obfs3,scramblesuit $BRIDGE_HOST:443 $fingerprint"
    #echo "Bridge obfs4 $BRIDGE_HOST:443 $fingerprint"
  done
) > /etc/tor/torrc.client

chown -R debian-tor:debian-tor /etc/tor
chown -R debian-tor:debian-tor /etc/torrc.d

# Push back up s3 bucket config directory for this tor node
aws s3 sync $TOR_DIR/$TOR_NICK/ s3://${s3_bucket}$TOR_DIR/$TOR_NICK/

# Push back the torrc client config
aws s3 cp /etc/tor/torrc.client s3://${s3_bucket}/torrc.client

# Allow tor to write to /etc/tor directory tree
if grep ReadWriteDirectories=-/etc/tor /lib/systemd/system/tor@default.service > /dev/null 2>&1; then
  echo "tor@default.service is already allowed to write to /etc/tor"
else
  sed -i -e 's%\(ReadWriteDirectories=-/proc\)%\1\nReadWriteDirectories=-/etc/tor%' /lib/systemd/system/tor@default.service
  systemctl daemon-reload
fi
# Allow tor to read from /etc/torrc.d directory
if grep '/etc/torrc.d/' /etc/apparmor.d/system_tor  > /dev/null 2>&1; then
  echo 'apparmor already setup for system_tor to allow /etc/torrc.d'
else
  sed -i -e 's%^\(.*/var/lib/tor/\*\* r,\)%\1\n  /etc/torrc.d/** r,%' /etc/apparmor.d/system_tor
fi

if [ ! -h /etc/apparmor.d/disable/system_tor ]; then
  ln -nsf /etc/apparmor.d/system_tor /etc/apparmor.d/disable/system_tor
fi

if systemctl -a | grep apparmor ; then
  systemctl stop apparmor
  systemctl disable apparmor
  reboot
fi

systemctl restart tor@default.service
systemctl restart tor

) 2>&1 | tee /tmp/tor-dfpk.log
