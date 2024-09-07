#!/bin/bash
# shellcheck disable=SC1091,SC2164,SC2034,SC1072,SC1073,SC1009

# Secure OpenVPN server installer for Debian, Ubuntu, CentOS, Amazon Linux 2, Fedora, Oracle Linux 8, Arch Linux, Rocky Linux and AlmaLinux.
# https://github.com/angristan/openvpn-install

SCRIPT_VERSION=2
SCRIPT_URL_ADDRESS="https://raw.githubusercontent.com/ExtremeDot/eXtremePanel/master/extPanel.sh"
USERCONTROL_SCRIPT="/etc/openvpn/userControl.sh"
DATABASE_JSON_FILE="/usr/local/etc/eXtremePanel/database/eXtremePanel.json"
PYTHON_VPNUSAGE_FILE="/usr/local/etc/eXtremePanel/database/vpn_usage_tracker.py"
CRON_JOB="* * * * * /usr/bin/python3 /usr/local/etc/eXtremePanel/database/vpn_usage_tracker.py"
CLIENT_TEMPLATE="/etc/openvpn/client-template.txt"
SERVER_CONFIG_FILE="/etc/openvpn/server.conf"


IP=""
PORT=""
DNS1_CONFIG="1.1.1.1"
DNS2_CONFIG="1.0.0.1"


if [ ! -d "/root/eXtremePanel/configs/" ]; then
    mkdir -p /root/eXtremePanel/configs/
fi

if [ ! -d "/usr/local/etc/eXtremePanel/database/" ]; then
    mkdir -p /usr/local/etc/eXtremePanel/database/
fi

if [ ! -d "/usr/local/etc/eXtremePanel/backup/" ]; then
    mkdir -p /usr/local/etc/eXtremePanel/backup/
fi


# Define color codes
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

function eXtpause() {
    echo ""
    read -p "Press Enter to continue..."  # Prompts the user and waits for Enter
    echo ""
}

function isRoot() {
	if [ "$EUID" -ne 0 ]; then
		return 1
	fi
}

function tunAvailable() {
	if [ ! -e /dev/net/tun ]; then
		return 1
	fi
}

function checkOS() {
	if [[ -e /etc/debian_version ]]; then
		OS="debian"
		source /etc/os-release

		if [[ $ID == "debian" || $ID == "raspbian" ]]; then
			if [[ $VERSION_ID -lt 9 ]]; then
				echo "⚠️ Your version of Debian is not supported."
				echo ""
				echo "However, if you're using Debian >= 9 or unstable/testing then you can continue, at your own risk."
				echo ""
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "Continue? [y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE == "n" ]]; then
					exit 1
				fi
			fi
		elif [[ $ID == "ubuntu" ]]; then
			OS="ubuntu"
			MAJOR_UBUNTU_VERSION=$(echo "$VERSION_ID" | cut -d '.' -f1)
			if [[ $MAJOR_UBUNTU_VERSION -lt 16 ]]; then
				echo "⚠️ Your version of Ubuntu is not supported."
				echo ""
				echo "However, if you're using Ubuntu >= 16.04 or beta, then you can continue, at your own risk."
				echo ""
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "Continue? [y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE == "n" ]]; then
					exit 1
				fi
			fi
		fi
	elif [[ -e /etc/system-release ]]; then
		source /etc/os-release
		if [[ $ID == "fedora" || $ID_LIKE == "fedora" ]]; then
			OS="fedora"
		fi
		if [[ $ID == "centos" || $ID == "rocky" || $ID == "almalinux" ]]; then
			OS="centos"
			if [[ ${VERSION_ID%.*} -lt 7 ]]; then
				echo "⚠️ Your version of CentOS is not supported."
				echo ""
				echo "The script only support CentOS 7 and CentOS 8."
				echo ""
				exit 1
			fi
		fi
		if [[ $ID == "ol" ]]; then
			OS="oracle"
			if [[ ! $VERSION_ID =~ (8) ]]; then
				echo "Your version of Oracle Linux is not supported."
				echo ""
				echo "The script only support Oracle Linux 8."
				exit 1
			fi
		fi
		if [[ $ID == "amzn" ]]; then
			OS="amzn"
			if [[ $VERSION_ID != "2" ]]; then
				echo "⚠️ Your version of Amazon Linux is not supported."
				echo ""
				echo "The script only support Amazon Linux 2."
				echo ""
				exit 1
			fi
		fi
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS, Amazon Linux 2, Oracle Linux 8 or Arch Linux system"
		exit 1
	fi
}

function initialCheck() {
	if ! isRoot; then
		echo -e "${RED}Sorry, you need to run this as root. ${NC}"
		exit 1
	fi
	if ! tunAvailable; then
		echo -e "${RED}TUN is not available. ${NC}"
		exit 1
	fi
	checkOS
}


function installResolveService() {
#!/bin/bash

# Check if nslookup github returns Server: 127.0.0.53
if nslookup github | grep -q "127.0.0.53"; then
    echo "Detected local DNS server (127.0.0.53)."

    # Check if resolvconf is installed
    if ! dpkg -l | grep -q resolvconf; then
        echo "resolvconf is not installed. Installing..."
        sudo apt-get install -y resolvconf
    else
        echo "resolvconf is already installed."
    fi

    # Add new nameserver entries
    echo "nameserver 1.1.1.1" | sudo tee /etc/resolvconf/resolv.conf.d/head > /dev/null
    echo "nameserver 1.0.0.1" | sudo tee -a /etc/resolvconf/resolv.conf.d/head > /dev/null
    echo "nameserver 2606:4700:4700::1111" | sudo tee -a /etc/resolvconf/resolv.conf.d/head > /dev/null
    echo "nameserver 2606:4700:4700::1001" | sudo tee -a /etc/resolvconf/resolv.conf.d/head > /dev/null

    # Restart resolvconf service
    sleep 1
    sudo systemctl enable resolvconf.service
    sudo systemctl start resolvconf.service
	sleep 1
    sudo resolvconf --enable-updates
	sleep 1
    sudo resolvconf -u

    echo "DNS configuration updated and resolvconf service restarted."
else
    echo "Local DNS server (127.0.0.53) not detected."
fi

}


function installUnbound() {
	# If Unbound isn't installed, install it
	if [[ ! -e /etc/unbound/unbound.conf ]]; then

		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get install -y unbound

			# Configuration
			echo 'interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes' >>/etc/unbound/unbound.conf

		elif [[ $OS =~ (centos|amzn|oracle) ]]; then
			yum install -y unbound

			# Configuration
			sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
			sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf
			sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf
			sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf
			sed -i 's|use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf

		elif [[ $OS == "fedora" ]]; then
			dnf install -y unbound

			# Configuration
			sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
			sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf
			sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf
			sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf
			sed -i 's|# use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf

		elif [[ $OS == "arch" ]]; then
			pacman -Syu --noconfirm unbound

			# Get root servers list
			curl -o /etc/unbound/root.hints https://www.internic.net/domain/named.cache

			if [[ ! -f /etc/unbound/unbound.conf.old ]]; then
				mv /etc/unbound/unbound.conf /etc/unbound/unbound.conf.old
			fi

			echo 'server:
	use-syslog: yes
	do-daemonize: no
	username: "unbound"
	directory: "/etc/unbound"
	trust-anchor-file: trusted-key.key
	root-hints: root.hints
	interface: 10.8.0.1
	access-control: 10.8.0.1/24 allow
	port: 53
	num-threads: 2
	use-caps-for-id: yes
	harden-glue: yes
	hide-identity: yes
	hide-version: yes
	qname-minimisation: yes
	prefetch: yes' >/etc/unbound/unbound.conf
		fi

		# IPv6 DNS for all OS
		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo 'interface: fd42:42:42:42::1
access-control: fd42:42:42:42::/112 allow' >>/etc/unbound/unbound.conf
		fi

		if [[ ! $OS =~ (fedora|centos|amzn|oracle) ]]; then
			# DNS Rebinding fix
			echo "private-address: 10.0.0.0/8
private-address: fd42:42:42:42::/112
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: fd00::/8
private-address: fe80::/10
private-address: 127.0.0.0/8
private-address: ::ffff:0:0/96" >>/etc/unbound/unbound.conf
		fi
	else # Unbound is already installed
		echo 'include: /etc/unbound/openvpn.conf' >>/etc/unbound/unbound.conf

		# Add Unbound 'server' for the OpenVPN subnet
		echo 'server:
interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes
private-address: 10.0.0.0/8
private-address: fd42:42:42:42::/112
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: fd00::/8
private-address: fe80::/10
private-address: 127.0.0.0/8
private-address: ::ffff:0:0/96' >/etc/unbound/openvpn.conf
		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo 'interface: fd42:42:42:42::1
access-control: fd42:42:42:42::/112 allow' >>/etc/unbound/openvpn.conf
		fi
	fi

	systemctl enable unbound
	systemctl restart unbound
}
check_jq_installed() {
    if ! command -v jq &> /dev/null; then
		echo -e "${YELLOW}jq is not installed. Trying to install it. ${NC}"
		apt install jq -y
    fi
}

check_jq_installed

clear 
# start
function installQuestions() {
	echo -e "${CYAN}Welcome to the eXtreme OpenVPN installer! ${NC}"
	echo ""

	echo "I need to ask you a few questions before starting the setup."
	echo "You can leave the default options and just press enter if you are ok with them."
	echo ""
	echo "I need to know the IPv4 address of the network interface you want OpenVPN listening to."
	echo "Unless your server is behind NAT, it should be your public IPv4 address."
	echo ""

	# Detect public IPv4 address and pre-fill for the user
	IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)

	if [[ -z $IP ]]; then
		# Detect public IPv6 address
		IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi
	APPROVE_IP=${APPROVE_IP:-n}
	if [[ $APPROVE_IP =~ n ]]; then
		read -rp "IP address: " -e -i "$IP" IP
	fi
	# If $IP is a private IP address, the server must be behind NAT
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo ""
		echo "It seems this server is behind NAT. What is its public IPv4 address or hostname?"
		echo "We need it for the clients to connect to the server."

		PUBLICIP=$(curl -s https://api.ipify.org)
		until [[ $ENDPOINT != "" ]]; do
			read -rp "Public IPv4 address or hostname: " -e -i "$PUBLICIP" ENDPOINT
		done
	fi

	echo ""
	echo "Checking for IPv6 connectivity..."
	echo ""
	# "ping6" and "ping -6" availability varies depending on the distribution
	if type ping6 >/dev/null 2>&1; then
		PING6="ping6 -c3 ipv6.google.com > /dev/null 2>&1"
	else
		PING6="ping -6 -c3 ipv6.google.com > /dev/null 2>&1"
	fi
	if eval "$PING6"; then
		echo "Your host appears to have IPv6 connectivity."
		SUGGESTION="y"
	else
		echo "Your host does not appear to have IPv6 connectivity."
		SUGGESTION="n"
	fi
	echo ""
	# Ask the user if they want to enable IPv6 regardless its availability.
	until [[ $IPV6_SUPPORT =~ (y|n) ]]; do
		read -rp "Do you want to enable IPv6 support (NAT)? [y/n]: " -e -i $SUGGESTION IPV6_SUPPORT
	done
	echo ""
	echo "What port do you want OpenVPN to listen to?"
	echo "   1) Default: 1194"
	echo "   2) Custom"
	echo -e "${YELLOW}   3) Random [10001-65535] ${NC}"
	until [[ $PORT_CHOICE =~ ^[1-3]$ ]]; do
		read -rp "Port choice [1-3]: " -e -i 3 PORT_CHOICE
	done
	case $PORT_CHOICE in
	1)
		PORT="1194"
		;;
	2)
		until [[ $PORT =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; do
			read -rp "Custom port [1-65535]: " -e -i 21194 PORT
		done
		;;
	3)
		# Generate random number within private ports range
		PORT=$(shuf -i10001-65535 -n1)
		echo "Random Port: $PORT"
		;;
	esac
	echo ""
	echo "What protocol do you want OpenVPN to use?"
	echo "UDP is faster. Unless it is not available, you shouldn't use TCP."
	echo "In Iran UDP is unstable. We have to use TCP."
	echo "   1) UDP"
	echo -e "${YELLOW}   2) TCP ${NC}"
	until [[ $PROTOCOL_CHOICE =~ ^[1-2]$ ]]; do
		read -rp "Protocol [1-2]: " -e -i 2 PROTOCOL_CHOICE
	done
	case $PROTOCOL_CHOICE in
	1)
		PROTOCOL="udp"
		;;
	2)
		PROTOCOL="tcp"
		;;
	esac
	echo ""
	echo "What DNS resolvers do you want to use with the VPN?"
	echo "   1) Current system resolvers (from /etc/resolv.conf)"
	echo "   2) Cloudflare (Anycast: worldwide)"
	echo "   3) Google (Anycast: worldwide)"
	echo -e "${YELLOW}   4) AdGuard DNS (Anycast: worldwide) ${NC}"
	echo "   5) Custom"
	until [[ $DNS =~ ^[0-9]+$ ]] && [ "$DNS" -ge 1 ] && [ "$DNS" -le 4 ]; do
		read -rp "DNS [1-12]: " -e -i 4 DNS
		if [[ $DNS == "5" ]]; then
			until [[ $DNS1 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
				read -rp "Primary DNS: " -e DNS1
			done
			until [[ $DNS2 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
				read -rp "Secondary DNS (optional): " -e DNS2
				if [[ $DNS2 == "" ]]; then
					break
				fi
			done
		fi
	done
	echo ""
	echo "Do you want to use compression? It is not recommended since the VORACLE attack makes use of it."
	until [[ $COMPRESSION_ENABLED =~ (y|n) ]]; do
		read -rp"Enable compression? [y/n]: " -e -i n COMPRESSION_ENABLED
	done
	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "Choose which compression algorithm you want to use: (they are ordered by efficiency)"
		echo "   1) LZ4-v2"
		echo "   2) LZ4"
		echo "   3) LZ0"
		until [[ $COMPRESSION_CHOICE =~ ^[1-3]$ ]]; do
			read -rp"Compression algorithm [1-3]: " -e -i 1 COMPRESSION_CHOICE
		done
		case $COMPRESSION_CHOICE in
		1)
			COMPRESSION_ALG="lz4-v2"
			;;
		2)
			COMPRESSION_ALG="lz4"
			;;
		3)
			COMPRESSION_ALG="lzo"
			;;
		esac
	fi
	echo ""
	echo "Do you want to customize encryption settings?"
	echo "Unless you know what you're doing, you should stick with the default parameters provided by the script."
	echo "Note that whatever you choose, all the choices presented in the script are safe. (Unlike OpenVPN's defaults)"
	echo "See https://github.com/angristan/openvpn-install#security-and-encryption to learn more."
	echo ""
	until [[ $CUSTOMIZE_ENC =~ (y|n) ]]; do
		read -rp "Customize encryption settings? [y/n]: " -e -i n CUSTOMIZE_ENC
	done
	if [[ $CUSTOMIZE_ENC == "n" ]]; then
		# Use default, sane and fast parameters
		CIPHER="AES-128-GCM"
		CERT_TYPE="1" # ECDSA
		CERT_CURVE="prime256v1"
		CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
		DH_TYPE="1" # ECDH
		DH_CURVE="prime256v1"
		HMAC_ALG="SHA256"
		TLS_SIG="1" # tls-crypt
	else
		echo ""
		echo "Choose which cipher you want to use for the data channel:"
		echo "   1) AES-128-GCM (recommended)"
		echo "   2) AES-192-GCM"
		echo "   3) AES-256-GCM"
		echo "   4) AES-128-CBC"
		echo "   5) AES-192-CBC"
		echo "   6) AES-256-CBC"
		until [[ $CIPHER_CHOICE =~ ^[1-6]$ ]]; do
			read -rp "Cipher [1-6]: " -e -i 1 CIPHER_CHOICE
		done
		case $CIPHER_CHOICE in
		1)
			CIPHER="AES-128-GCM"
			;;
		2)
			CIPHER="AES-192-GCM"
			;;
		3)
			CIPHER="AES-256-GCM"
			;;
		4)
			CIPHER="AES-128-CBC"
			;;
		5)
			CIPHER="AES-192-CBC"
			;;
		6)
			CIPHER="AES-256-CBC"
			;;
		esac
		echo ""
		echo "Choose what kind of certificate you want to use:"
		echo "   1) ECDSA (recommended)"
		echo "   2) RSA"
		until [[ $CERT_TYPE =~ ^[1-2]$ ]]; do
			read -rp"Certificate key type [1-2]: " -e -i 1 CERT_TYPE
		done
		case $CERT_TYPE in
		1)
			echo ""
			echo "Choose which curve you want to use for the certificate's key:"
			echo "   1) prime256v1 (recommended)"
			echo "   2) secp384r1"
			echo "   3) secp521r1"
			until [[ $CERT_CURVE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp"Curve [1-3]: " -e -i 1 CERT_CURVE_CHOICE
			done
			case $CERT_CURVE_CHOICE in
			1)
				CERT_CURVE="prime256v1"
				;;
			2)
				CERT_CURVE="secp384r1"
				;;
			3)
				CERT_CURVE="secp521r1"
				;;
			esac
			;;
		2)
			echo ""
			echo "Choose which size you want to use for the certificate's RSA key:"
			echo "   1) 2048 bits (recommended)"
			echo "   2) 3072 bits"
			echo "   3) 4096 bits"
			until [[ $RSA_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp "RSA key size [1-3]: " -e -i 1 RSA_KEY_SIZE_CHOICE
			done
			case $RSA_KEY_SIZE_CHOICE in
			1)
				RSA_KEY_SIZE="2048"
				;;
			2)
				RSA_KEY_SIZE="3072"
				;;
			3)
				RSA_KEY_SIZE="4096"
				;;
			esac
			;;
		esac
		echo ""
		echo "Choose which cipher you want to use for the control channel:"
		case $CERT_TYPE in
		1)
			echo "   1) ECDHE-ECDSA-AES-128-GCM-SHA256 (recommended)"
			echo "   2) ECDHE-ECDSA-AES-256-GCM-SHA384"
			until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
				read -rp"Control channel cipher [1-2]: " -e -i 1 CC_CIPHER_CHOICE
			done
			case $CC_CIPHER_CHOICE in
			1)
				CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
				;;
			2)
				CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"
				;;
			esac
			;;
		2)
			echo "   1) ECDHE-RSA-AES-128-GCM-SHA256 (recommended)"
			echo "   2) ECDHE-RSA-AES-256-GCM-SHA384"
			until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
				read -rp"Control channel cipher [1-2]: " -e -i 1 CC_CIPHER_CHOICE
			done
			case $CC_CIPHER_CHOICE in
			1)
				CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"
				;;
			2)
				CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"
				;;
			esac
			;;
		esac
		echo ""
		echo "Choose what kind of Diffie-Hellman key you want to use:"
		echo "   1) ECDH (recommended)"
		echo "   2) DH"
		until [[ $DH_TYPE =~ [1-2] ]]; do
			read -rp"DH key type [1-2]: " -e -i 1 DH_TYPE
		done
		case $DH_TYPE in
		1)
			echo ""
			echo "Choose which curve you want to use for the ECDH key:"
			echo "   1) prime256v1 (recommended)"
			echo "   2) secp384r1"
			echo "   3) secp521r1"
			while [[ $DH_CURVE_CHOICE != "1" && $DH_CURVE_CHOICE != "2" && $DH_CURVE_CHOICE != "3" ]]; do
				read -rp"Curve [1-3]: " -e -i 1 DH_CURVE_CHOICE
			done
			case $DH_CURVE_CHOICE in
			1)
				DH_CURVE="prime256v1"
				;;
			2)
				DH_CURVE="secp384r1"
				;;
			3)
				DH_CURVE="secp521r1"
				;;
			esac
			;;
		2)
			echo ""
			echo "Choose what size of Diffie-Hellman key you want to use:"
			echo "   1) 2048 bits (recommended)"
			echo "   2) 3072 bits"
			echo "   3) 4096 bits"
			until [[ $DH_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp "DH key size [1-3]: " -e -i 1 DH_KEY_SIZE_CHOICE
			done
			case $DH_KEY_SIZE_CHOICE in
			1)
				DH_KEY_SIZE="2048"
				;;
			2)
				DH_KEY_SIZE="3072"
				;;
			3)
				DH_KEY_SIZE="4096"
				;;
			esac
			;;
		esac
		echo ""
		# The "auth" options behaves differently with AEAD ciphers
		if [[ $CIPHER =~ CBC$ ]]; then
			echo "The digest algorithm authenticates data channel packets and tls-auth packets from the control channel."
		elif [[ $CIPHER =~ GCM$ ]]; then
			echo "The digest algorithm authenticates tls-auth packets from the control channel."
		fi
		echo "Which digest algorithm do you want to use for HMAC?"
		echo "   1) SHA-256 (recommended)"
		echo "   2) SHA-384"
		echo "   3) SHA-512"
		until [[ $HMAC_ALG_CHOICE =~ ^[1-3]$ ]]; do
			read -rp "Digest algorithm [1-3]: " -e -i 1 HMAC_ALG_CHOICE
		done
		case $HMAC_ALG_CHOICE in
		1)
			HMAC_ALG="SHA256"
			;;
		2)
			HMAC_ALG="SHA384"
			;;
		3)
			HMAC_ALG="SHA512"
			;;
		esac
		echo ""
		echo "You can add an additional layer of security to the control channel with tls-auth and tls-crypt"
		echo "tls-auth authenticates the packets, while tls-crypt authenticate and encrypt them."
		echo -e "${YELLOW}   1) tls-crypt (recommended) ${NC}"
		echo "   2) tls-auth"
		until [[ $TLS_SIG =~ [1-2] ]]; do
			read -rp "Control channel additional security mechanism [1-2]: " -e -i 1 TLS_SIG
		done
	fi
	echo ""
	echo "Okay, that was all I needed. We are ready to setup your OpenVPN server now."
	echo "You will be able to generate a client at the end of the installation."
	APPROVE_INSTALL=${APPROVE_INSTALL:-n}
	if [[ $APPROVE_INSTALL =~ n ]]; then
		read -n1 -r -p "Press any key to continue..."
	fi
}

function installOpenVPN() {
	if [[ $AUTO_INSTALL == "y" ]]; then
		# Set default choices so that no questions will be asked.
		APPROVE_INSTALL=${APPROVE_INSTALL:-y}
		APPROVE_IP=${APPROVE_IP:-y}
		IPV6_SUPPORT=${IPV6_SUPPORT:-n}
		PORT_CHOICE=${PORT_CHOICE:-1}
		PROTOCOL_CHOICE=${PROTOCOL_CHOICE:-1}
		DNS=${DNS:-1}
		COMPRESSION_ENABLED=${COMPRESSION_ENABLED:-n}
		CUSTOMIZE_ENC=${CUSTOMIZE_ENC:-n}
		CLIENT=${CLIENT:-client}
		PASS=${PASS:-1}
		CONTINUE=${CONTINUE:-y}

		# Behind NAT, we'll default to the publicly reachable IPv4/IPv6.
		if [[ $IPV6_SUPPORT == "y" ]]; then
			if ! PUBLIC_IP=$(curl -f --retry 5 --retry-connrefused https://ip.seeip.org); then
				PUBLIC_IP=$(dig -6 TXT +short o-o.myaddr.l.google.com @ns1.google.com | tr -d '"')
			fi
		else
			if ! PUBLIC_IP=$(curl -f --retry 5 --retry-connrefused -4 https://ip.seeip.org); then
				PUBLIC_IP=$(dig -4 TXT +short o-o.myaddr.l.google.com @ns1.google.com | tr -d '"')
			fi
		fi
		ENDPOINT=${ENDPOINT:-$PUBLIC_IP}
	fi

	# Run setup questions first, and set other variables if auto-install
	installQuestions

	# Get the "public" interface from the default route
	NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
	if [[ -z $NIC ]] && [[ $IPV6_SUPPORT == 'y' ]]; then
		NIC=$(ip -6 route show default | sed -ne 's/^default .* dev \([^ ]*\) .*$/\1/p')
	fi

	# $NIC can not be empty for script rm-openvpn-rules.sh
	if [[ -z $NIC ]]; then
		echo
		echo "Can not detect public interface."
		echo "This needs for setup MASQUERADE."
		until [[ $CONTINUE =~ (y|n) ]]; do
			read -rp "Continue? [y/n]: " -e CONTINUE
		done
		if [[ $CONTINUE == "n" ]]; then
			exit 1
		fi
	fi

	# If OpenVPN isn't installed yet, install it. This script is more-or-less
	# idempotent on multiple runs, but will only install OpenVPN from upstream
	# the first time.
	if [[ ! -e $SERVER_CONFIG_FILE ]]; then
		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get update
			apt-get -y install ca-certificates gnupg
			# We add the OpenVPN repo to get the latest version.
			if [[ $VERSION_ID == "16.04" ]]; then
				echo "deb http://build.openvpn.net/debian/openvpn/stable xenial main" >/etc/apt/sources.list.d/openvpn.list
				wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
				apt-get update
			fi
			# Ubuntu > 16.04 and Debian > 8 have OpenVPN >= 2.4 without the need of a third party repository.
			apt-get install -y openvpn iptables openssl wget ca-certificates curl
		elif [[ $OS == 'centos' ]]; then
			yum install -y epel-release
			yum install -y openvpn iptables openssl wget ca-certificates curl tar 'policycoreutils-python*'
		elif [[ $OS == 'oracle' ]]; then
			yum install -y oracle-epel-release-el8
			yum-config-manager --enable ol8_developer_EPEL
			yum install -y openvpn iptables openssl wget ca-certificates curl tar policycoreutils-python-utils
		elif [[ $OS == 'amzn' ]]; then
			amazon-linux-extras install -y epel
			yum install -y openvpn iptables openssl wget ca-certificates curl
		elif [[ $OS == 'fedora' ]]; then
			dnf install -y openvpn iptables openssl wget ca-certificates curl policycoreutils-python-utils
		elif [[ $OS == 'arch' ]]; then
			# Install required dependencies and upgrade the system
			pacman --needed --noconfirm -Syu openvpn iptables openssl wget ca-certificates curl
		fi
		# An old version of easy-rsa was available by default in some openvpn packages
		if [[ -d /etc/openvpn/easy-rsa/ ]]; then
			rm -rf /etc/openvpn/easy-rsa/
		fi
	fi

	# Find out if the machine uses nogroup or nobody for the permissionless group
	if grep -qs "^nogroup:" /etc/group; then
		NOGROUP=nogroup
	else
		NOGROUP=nobody
	fi

	# Install the latest version of easy-rsa from source, if not already installed.
	if [[ ! -d /etc/openvpn/easy-rsa/ ]]; then
		local version="3.1.2"
		wget -O ~/easy-rsa.tgz https://github.com/OpenVPN/easy-rsa/releases/download/v${version}/EasyRSA-${version}.tgz
		mkdir -p /etc/openvpn/easy-rsa
		tar xzf ~/easy-rsa.tgz --strip-components=1 --no-same-owner --directory /etc/openvpn/easy-rsa
		rm -f ~/easy-rsa.tgz

		cd /etc/openvpn/easy-rsa/ || return
		case $CERT_TYPE in
		1)
			echo "set_var EASYRSA_ALGO ec" >vars
			echo "set_var EASYRSA_CURVE $CERT_CURVE" >>vars
			;;
		2)
			echo "set_var EASYRSA_KEY_SIZE $RSA_KEY_SIZE" >vars
			;;
		esac

		# Generate a random, alphanumeric identifier of 16 characters for CN and one for server name
		SERVER_CN="cn_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
		echo "$SERVER_CN" >SERVER_CN_GENERATED
		SERVER_NAME="server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
		echo "$SERVER_NAME" >SERVER_NAME_GENERATED

		# Create the PKI, set up the CA, the DH params and the server certificate
		./easyrsa init-pki
		EASYRSA_CA_EXPIRE=3650 ./easyrsa --batch --req-cn="$SERVER_CN" build-ca nopass

		if [[ $DH_TYPE == "2" ]]; then
			# ECDH keys are generated on-the-fly so we don't need to generate them beforehand
			openssl dhparam -out dh.pem $DH_KEY_SIZE
		fi

		EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-server-full "$SERVER_NAME" nopass
		EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

		case $TLS_SIG in
		1)
			# Generate tls-crypt key
			openvpn --genkey secret /etc/openvpn/tls-crypt.key
			;;
		2)
			# Generate tls-auth key
			openvpn --genkey secret /etc/openvpn/tls-auth.key
			;;
		esac
	else
		# If easy-rsa is already installed, grab the generated SERVER_NAME
		# for client configs
		cd /etc/openvpn/easy-rsa/ || return
		SERVER_NAME=$(cat SERVER_NAME_GENERATED)
	fi

	# Move all the generated files
	cp pki/ca.crt pki/private/ca.key "pki/issued/$SERVER_NAME.crt" "pki/private/$SERVER_NAME.key" /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
	if [[ $DH_TYPE == "2" ]]; then
		cp dh.pem /etc/openvpn
	fi

	# Make cert revocation list readable for non-root
	chmod 644 /etc/openvpn/crl.pem

	# Generate server.conf
	echo "port $PORT" >$SERVER_CONFIG_FILE
	if [[ $IPV6_SUPPORT == 'n' ]]; then
		echo "proto $PROTOCOL" >> $SERVER_CONFIG_FILE
	elif [[ $IPV6_SUPPORT == 'y' ]]; then
		echo "proto ${PROTOCOL}6" >> $SERVER_CONFIG_FILE
	fi

	echo "dev tun
user nobody
group $NOGROUP
persist-key
persist-tun
keepalive 10 120
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" >> $SERVER_CONFIG_FILE

	# DNS resolvers
	case $DNS in
	1) # Current system resolvers
		# Locate the proper resolv.conf
		# Needed for systems running systemd-resolved
		if grep -q "127.0.0.53" "/etc/resolv.conf"; then
			RESOLVCONF='/run/systemd/resolve/resolv.conf'
		else
			RESOLVCONF='/etc/resolv.conf'
		fi
		# Obtain the resolvers from resolv.conf and use them for OpenVPN
		sed -ne 's/^nameserver[[:space:]]\+\([^[:space:]]\+\).*$/\1/p' $RESOLVCONF | while read -r line; do
			# Copy, if it's a IPv4 |or| if IPv6 is enabled, IPv4/IPv6 does not matter
			if [[ $line =~ ^[0-9.]*$ ]] || [[ $IPV6_SUPPORT == 'y' ]]; then
				echo "push \"dhcp-option DNS $line\"" >> $SERVER_CONFIG_FILE
			fi
		done
		;;
	2) # Cloudflare
		echo 'push "dhcp-option DNS 1.0.0.1"' >> $SERVER_CONFIG_FILE
		echo 'push "dhcp-option DNS 1.1.1.1"' >> $SERVER_CONFIG_FILE
		DNS1_CONFIG="1.1.1.1"
		DNS2_CONFIG="1.0.0.1"
		;;
	3) # Google
		echo 'push "dhcp-option DNS 8.8.8.8"' >> $SERVER_CONFIG_FILE
		echo 'push "dhcp-option DNS 8.8.4.4"' >> $SERVER_CONFIG_FILE
		DNS1_CONFIG="8.8.8.8"
		DNS2_CONFIG="8.8.4.4"
		;;
	4) # AdGuard DNS
		echo 'push "dhcp-option DNS 94.140.14.14"' >> $SERVER_CONFIG_FILE
		echo 'push "dhcp-option DNS 94.140.15.15"' >> $SERVER_CONFIG_FILE
		DNS1_CONFIG="94.140.14.14"
		DNS2_CONFIG="94.140.15.15"
		;;
	5) # Custom DNS
		echo "push \"dhcp-option DNS $DNS1\"" >> $SERVER_CONFIG_FILE
		DNS1_CONFIG="$DNS1"
		if [[ $DNS2 != "" ]]; then
			echo "push \"dhcp-option DNS $DNS2\"" >> $SERVER_CONFIG_FILE
			DNS2_CONFIG="$DNS2"
		fi
		;;
	esac
	echo 'push "redirect-gateway def1 bypass-dhcp"' >> $SERVER_CONFIG_FILE

	# IPv6 network settings if needed
	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo 'server-ipv6 fd42:42:42:42::/112
tun-ipv6
push tun-ipv6
push "route-ipv6 2000::/3"
push "redirect-gateway ipv6"' >> $SERVER_CONFIG_FILE
	fi

	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "compress $COMPRESSION_ALG" >> $SERVER_CONFIG_FILE
	fi

	if [[ $DH_TYPE == "1" ]]; then
		echo "dh none" >> $SERVER_CONFIG_FILE
		echo "ecdh-curve $DH_CURVE" >> $SERVER_CONFIG_FILE
	elif [[ $DH_TYPE == "2" ]]; then
		echo "dh /etc/openvpn/dh.pem" >> $SERVER_CONFIG_FILE
	fi

	case $TLS_SIG in
	1)
		echo "tls-crypt /etc/openvpn/tls-crypt.key" >> $SERVER_CONFIG_FILE
		;;
	2)
		echo "tls-auth /etc/openvpn/tls-auth.key 0" >> $SERVER_CONFIG_FILE
		;;
	esac

	echo "crl-verify /etc/openvpn/crl.pem
ca /etc/openvpn/ca.crt
cert /etc/openvpn/$SERVER_NAME.crt
key /etc/openvpn/$SERVER_NAME.key
auth $HMAC_ALG
cipher $CIPHER
data-ciphers $CIPHER
tls-server
tls-version-min 1.2
tls-cipher $CC_CIPHER
client-config-dir /etc/openvpn/ccd
status /var/log/openvpn/status.log
script-security 2
client-connect /etc/openvpn/userControl.sh
verb 3" >> $SERVER_CONFIG_FILE

	# Create client-config-dir dir
	mkdir -p /etc/openvpn/ccd
	# Create log dir
	mkdir -p /var/log/openvpn
	# Make cron job
	(crontab -l | grep -F "$CRON_JOB") &> /dev/null

	if [ $? -ne 0 ]; then
	    (crontab -l; echo "$CRON_JOB") | crontab -
	    echo "Cron job added: $CRON_JOB"
	else
	    echo "Cron job already exists: $CRON_JOB"
	fi
	# Create usercontrol script
	if [ ! -f "$USERCONTROL_SCRIPT" ]; then
	    cat << 'EOF' > "$USERCONTROL_SCRIPT"
#!/bin/bash

COMMON_NAME="${common_name}"
JSON_FILE="/usr/local/etc/eXtremePanel/database/eXtremePanel.json"

ACTIVE=$(jq -r --arg user "$COMMON_NAME" '.users[$user].active' "$JSON_FILE")

if [ "$ACTIVE" == "true" ]; then
    exit 0
else
    exit 1
fi
EOF

	    chmod +wrx "$USERCONTROL_SCRIPT"
	fi

	# Make vpn usage tracker
	if [ ! -f "$PYTHON_VPNUSAGE_FILE" ]; then
	    cat << 'EOF' > "$PYTHON_VPNUSAGE_FILE"
import json
import os
import logging

DATABASE_JSON_FILE = "/usr/local/etc/eXtremePanel/database/eXtremePanel.json"
STATUS_LOG = "/var/log/openvpn/status.log"
logging.basicConfig(filename='/var/log/vpn_usage_tracker.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_data():
    """Load existing data from the JSON file."""
    if os.path.exists(DATABASE_JSON_FILE):
        with open(DATABASE_JSON_FILE, 'r') as file:
            return json.load(file)
    return {}

def save_data(data):
    """Save data back to the JSON file."""
    with open(DATABASE_JSON_FILE, 'w') as file:
        json.dump(data, file, indent=4)

def parse_status_log():
    """Parse the status.log to extract user data including IP addresses."""
    users = {}
    try:
        with open(STATUS_LOG, 'r') as file:
            lines = file.readlines()
        in_client_list = False
        for line in lines:
            if line.startswith("OpenVPN CLIENT LIST"):
                in_client_list = True
                continue
            if line.startswith("ROUTING TABLE"):
                in_client_list = False
            if in_client_list and line and not line.startswith("Common Name"):
                parts = line.split(',')
                if len(parts) >= 4:
                    username = parts[0].strip()
                    try:
                        bytes_received = int(parts[2].strip())
                        bytes_sent = int(parts[3].strip())
                        last_ip = parts[1].strip().split(':')[0]
                        users[username] = {
                            'bytes_received': bytes_received,
                            'bytes_sent': bytes_sent,
                            'last_ip': last_ip
                        }
                    except ValueError as e:
                        logging.warning(f"ValueError: {e} for line: {line}")
                else:
                    logging.warning(f"Unexpected line format: {line}")
    except Exception as e:
        logging.error(f"Error parsing status log: {e}")
    return users

def update_user_traffic():
    """Update user traffic and IP information in the JSON file."""
    data = load_data()
    current_usage = parse_status_log()
    for username, stats in current_usage.items():
        bytes_received = stats['bytes_received']
        bytes_sent = stats['bytes_sent']
        last_ip = stats['last_ip']
        if username in data['users']:
            user_data = data['users'][username]
            openvpn_data = user_data['vpn_services']['openvpn']
            upload_gb = bytes_sent / (1024 * 1024 * 1024)
            download_gb = bytes_received / (1024 * 1024 * 1024)
            total_usage_gb = upload_gb + download_gb
            openvpn_data['upload_GB'] += upload_gb
            openvpn_data['download_GB'] += download_gb
            openvpn_data['total_usage_GB'] += total_usage_gb
            user_data['total_upload_GB'] += upload_gb
            user_data['total_download_GB'] += download_gb
            user_data['total_usage_GB'] += total_usage_gb
            openvpn_data['last_connected_ip'] = last_ip
            user_data['last_ip'] = last_ip
            data_usage = user_data['data_usage']
            remaining_data_gb = data_usage - user_data['total_usage_GB']
            user_data['remaining_data_GB'] = remaining_data_gb
            if remaining_data_gb <= 0:
                user_data['active'] = False
                logging.info(f"User {username} has exceeded data usage limit and is now inactive.")
        else:
            logging.warning(f"User {username} not found in eXtremePanel database.")
    save_data(data)

def main():
    try:
        update_user_traffic()
    except Exception as e:
        logging.error(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
EOF

	    chmod +wrx "$PYTHON_VPNUSAGE_FILE"
	fi



	# Enable routing
	echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn.conf
	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo 'net.ipv6.conf.all.forwarding=1' >>/etc/sysctl.d/99-openvpn.conf
	fi
	# Apply sysctl rules
	sysctl --system

	# If SELinux is enabled and a custom port was selected, we need this
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ $PORT != '1194' ]]; then
				semanage port -a -t openvpn_port_t -p "$PROTOCOL" "$PORT"
			fi
		fi
	fi

	# Finally, restart and enable OpenVPN
	if [[ $OS == 'arch' || $OS == 'fedora' || $OS == 'centos' || $OS == 'oracle' ]]; then
		# Don't modify package-provided service
		cp /usr/lib/systemd/system/openvpn-server@.service /etc/systemd/system/openvpn-server@.service

		# Workaround to fix OpenVPN service on OpenVZ
		sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn-server@.service
		# Another workaround to keep using /etc/openvpn/
		sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn-server@.service

		systemctl daemon-reload
		systemctl enable openvpn-server@server
		systemctl restart openvpn-server@server
	elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
		# On Ubuntu 16.04, we use the package from the OpenVPN repo
		# This package uses a sysvinit service
		systemctl enable openvpn
		systemctl start openvpn
	else
		# Don't modify package-provided service
		cp /lib/systemd/system/openvpn\@.service /etc/systemd/system/openvpn\@.service

		# Workaround to fix OpenVPN service on OpenVZ
		sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn\@.service
		# Another workaround to keep using /etc/openvpn/
		sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn\@.service

		systemctl daemon-reload
		systemctl enable openvpn@server
		systemctl restart openvpn@server
	fi

	if [[ $DNS == 2 ]]; then
		installUnbound
	fi

	# Add iptables rules in two scripts
	mkdir -p /etc/iptables

	# Script to add rules
	echo "#!/bin/sh
iptables -t nat -I POSTROUTING 1 -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -I INPUT 1 -i tun0 -j ACCEPT
iptables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
iptables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
iptables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/add-openvpn-rules.sh

	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo "ip6tables -t nat -I POSTROUTING 1 -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -I INPUT 1 -i tun0 -j ACCEPT
ip6tables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
ip6tables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
ip6tables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/add-openvpn-rules.sh
	fi

	# Script to remove rules
	echo "#!/bin/sh
iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -D INPUT -i tun0 -j ACCEPT
iptables -D FORWARD -i $NIC -o tun0 -j ACCEPT
iptables -D FORWARD -i tun0 -o $NIC -j ACCEPT
iptables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/rm-openvpn-rules.sh

	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo "ip6tables -t nat -D POSTROUTING -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -D INPUT -i tun0 -j ACCEPT
ip6tables -D FORWARD -i $NIC -o tun0 -j ACCEPT
ip6tables -D FORWARD -i tun0 -o $NIC -j ACCEPT
ip6tables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/rm-openvpn-rules.sh
	fi

	chmod +x /etc/iptables/add-openvpn-rules.sh
	chmod +x /etc/iptables/rm-openvpn-rules.sh

	# Handle the rules via a systemd script
	echo "[Unit]
Description=iptables rules for OpenVPN
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/iptables/add-openvpn-rules.sh
ExecStop=/etc/iptables/rm-openvpn-rules.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" >/etc/systemd/system/iptables-openvpn.service

	# Enable service and apply rules
	systemctl daemon-reload
	systemctl enable iptables-openvpn
	systemctl start iptables-openvpn

	# If the server is behind a NAT, use the correct IP address for the clients to connect to
	if [[ $ENDPOINT != "" ]]; then
		IP=$ENDPOINT
	fi

	# client-template.txt is created so we have a template to add further users later
	echo "client" >$CLIENT_TEMPLATE
	if [[ $PROTOCOL == 'udp' ]]; then
		echo "proto udp" >> $CLIENT_TEMPLATE
		echo "explicit-exit-notify" >> $CLIENT_TEMPLATE
	elif [[ $PROTOCOL == 'tcp' ]]; then
		echo "proto tcp-client" >> $CLIENT_TEMPLATE
	fi
	echo "remote $IP $PORT
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name $SERVER_NAME name
auth $HMAC_ALG
auth-nocache
cipher $CIPHER
tls-client
tls-version-min 1.2
tls-cipher $CC_CIPHER
ignore-unknown-option block-outside-dns
setenv opt block-outside-dns
verb 3
" >> $CLIENT_TEMPLATE

	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "compress $COMPRESSION_ALG" >> $CLIENT_TEMPLATE
	fi
	
	#############
	# Check if the file does not exist
	if [ ! -f "$DATABASE_JSON_FILE" ]; then
		# Create the file with the specified content
		mkdir -p "$(dirname "$DATABASE_JSON_FILE")" # Create the directory if it doesn't exist
		cat << EOF > "$DATABASE_JSON_FILE"
{
	"settings": {
		"app_name": "eXtremePanel",
		"backup_path": "/usr/local/etc/eXtremePanel/backup",
		"server_config_path": "/root/eXtremePanel/configs",
		"domain": "auto.eXtreme.com",
		"openVPN_port": "1194",
		"openVPN_DNS1": "1.1.1.1",
		"openVPN_DNS2": "1.0.0.1",
		"wireGuard_port": "38500",
		"wireGuard_DNS1": "8.8.8.8",
		"wireGuard_DNS2": "8.8.4.4"
	},
	"users": {
		"def_template": {
			"password": "x125asd",
			"expiration_date": "2012-12-12",
			"max_ip_limit": "2",
			"data_usage": 30,
			"active": true,
			"last_ip": "192.168.1.10",
			"vpn_services": {
				"openvpn": {
					"config_path": "/root/eXtremePanel/configs/def_template_openvpn.conf",
					"last_connected_ip": "192.168.1.20",
					"upload_GB": 2.5,
					"download_GB": 3.0,
					"total_usage_GB": 5.5
				},
				"wireguard": {
					"public_key": "x123as5d1azx32a1sd5a6sd12as",
					"allowed_ips": "10.0.0.2/32",
					"endpoint": "auto.eXtreme.com:51820",
					"config_path": "/root/eXtremePanel/configs/def_template_wireguard.conf",
					"last_connected_ip": "192.168.1.21",
					"upload_GB": 1.0,
					"download_GB": 1.5,
					"total_usage_GB": 2.5
				}
			},
			"total_upload_GB": 3.5,
			"total_download_GB": 4.5,
			"total_usage_GB": 8.0,
			"remaining_data_GB": 22
		}
	}
}
EOF
		echo "File created: $DATABASE_JSON_FILE"
	else
		echo "File already exists: $DATABASE_JSON_FILE"
	fi

	### update the new values
	# Update the JSON file using jq
	
	jq --arg ip "$IP" \
	   --arg port "$PORT" \
	   --arg dns1 "$DNS1_CONFIG" \
	   --arg dns2 "$DNS2_CONFIG" \
	   '.settings.domain = $ip | .settings.openVPN_port = $port | .settings.openVPN_DNS1 = $dns1 | .settings.openVPN_DNS2 = $dns2' \
	   "$DATABASE_JSON_FILE" > tmp.$$.json && mv tmp.$$.json "$DATABASE_JSON_FILE"

	# Generate the custom client.ovpn
	newClient
	echo "If you want to add more clients, you simply need to run this script another time!"
}

function editClient() {

    # Initialize variables
    EXTEND_DAYS=""
    USER_PASSS=""
    TRAFFIC_LIMIT=""
    MAX_IP_LIMIT=""
    ACTIVE=""

    
	# Function to read current value from JSON
    getCurrentValue() {
        jq -r --arg client "$CLIENT" ".users[\$client].$1 // empty" "$DATABASE_JSON_FILE"
    }

    clear
	echo ""
	echo "User Editor Menu-----------------------------------------------"
	echo ""
	echo "Selected Username: [ $CLIENT ]"
	echo
    # Ask for the User Password
    CURRENT_PASS=$(getCurrentValue "password")
    read -p "Enter the User Password (current: $CURRENT_PASS): " USER_PASSS
    USER_PASSS=${USER_PASSS:-$CURRENT_PASS}  # Keep current if no input

    echo ""
    # Ask for the traffic limit in GB, default is current or 50
    CURRENT_TRAFFIC=$(getCurrentValue "data_usage")
    read -p "Enter the Traffic Limit in GB (current: ${CURRENT_TRAFFIC:-50}): " TRAFFIC_LIMIT
    TRAFFIC_LIMIT=${TRAFFIC_LIMIT:-$CURRENT_TRAFFIC}  # Keep current if no input

    echo ""
    # Fetch the current expiration date from the JSON file
	CURRENT_EXPIRATION_DATE=$(getCurrentValue "expiration_date")

	# Calculate remaining days if the current expiration date exists
	if [[ -n "$CURRENT_EXPIRATION_DATE" ]]; then
		TODAY=$(date +%Y-%m-%d)
		REMAINING_DAYS=$(( ( $(date -d "$CURRENT_EXPIRATION_DATE" +%s) - $(date -d "$TODAY" +%s) ) / 86400 ))

		if [[ $REMAINING_DAYS -lt 0 ]]; then
			echo -e "${RED}Current expiration date is $CURRENT_EXPIRATION_DATE (Expired)${NC}"
			REMAINING_DAYS="EXPIRED"			
		else
			echo "Current expiration date is $CURRENT_EXPIRATION_DATE ($REMAINING_DAYS days remaining)"
		fi
	else
		echo "Current expiration date is not set."
		REMAINING_DAYS="N/A"
	fi

	# Ask for the number of days to extend the expiration
	read -p "Enter the number of days to extend (Remaining Days: $REMAINING_DAYS): " EXTEND_DAYS

	# If the user provides a new value, calculate the new expiration date; otherwise, keep the current
	if [ -n "$EXTEND_DAYS" ]; then
		EXTEND_DAYS=$(date -d "+$EXTEND_DAYS days" +"%Y-%m-%d")
	else
		EXTEND_DAYS=$CURRENT_EXPIRATION_DATE  # Keep current if no input
	fi


    # Ask for max IP limit with default value of current or 2
    CURRENT_MAX_IP=$(getCurrentValue "max_ip_limit")
    read -p "Enter max IP limit (current: ${CURRENT_MAX_IP:-2}): " MAX_IP_LIMIT
    MAX_IP_LIMIT=${MAX_IP_LIMIT:-$CURRENT_MAX_IP}

    # Validate max IP limit range
    if ! [[ "$MAX_IP_LIMIT" =~ ^[0-9]$ ]] || [ "$MAX_IP_LIMIT" -gt 9 ]; then
        echo -e "${RED}Invalid input for max IP limit. Must be between 0 and 9. ${NC}"
        exit 1
    fi

    # Ask for the active status (0 for false, 1 for true), default is current
    CURRENT_ACTIVE=$(getCurrentValue "active")
    CURRENT_ACTIVE=${CURRENT_ACTIVE,,}  # Convert to lowercase to handle "true" or "false"
    CURRENT_ACTIVE=${CURRENT_ACTIVE/true/1}
    CURRENT_ACTIVE=${CURRENT_ACTIVE/false/0}
    read -p "Is the account active? (0 for No, 1 for Yes, current: ${CURRENT_ACTIVE:-1}): " ACTIVE
    ACTIVE=${ACTIVE:-$CURRENT_ACTIVE}  # Keep current if no input

    # Convert numeric input to boolean
    if [[ "$ACTIVE" == "1" ]]; then
        ACTIVE=true
    else
        ACTIVE=false
    fi

    # Update the JSON file only with provided values
    jq --arg client "$CLIENT" \
       --arg exp_date "$EXTEND_DAYS" \
       --argjson max_ip "$MAX_IP_LIMIT" \
       --arg active "$ACTIVE" \
       --arg password "$USER_PASSS" \
       --argjson data_usage "$TRAFFIC_LIMIT" \
       --argjson zero 0 \
       '.users[$client] //= {} |
        .users[$client].expiration_date = $exp_date |
        .users[$client].max_ip_limit = $max_ip |
        .users[$client].active = ($active == "true") |
        .users[$client].password = $password |
        .users[$client].data_usage = $data_usage |
        .users[$client].vpn_services.openvpn.upload_GB = $zero |
        .users[$client].vpn_services.openvpn.download_GB = $zero |
        .users[$client].vpn_services.openvpn.total_usage_GB = $zero |
        .users[$client].vpn_services.openvpn.last_connected_ip = "192.168.1.1" |
        .users[$client].vpn_services.wireguard.upload_GB = $zero |
        .users[$client].vpn_services.wireguard.download_GB = $zero |
        .users[$client].vpn_services.wireguard.total_usage_GB = $zero |
        .users[$client].vpn_services.wireguard.last_connected_ip = "192.168.0.1" |
        .users[$client].total_upload_GB = $zero |
        .users[$client].total_download_GB = $zero |
        .users[$client].total_usage_GB = $zero |
        .users[$client].remaining_data_GB = $data_usage' \
       "$DATABASE_JSON_FILE" > tmp.$$.json && mv tmp.$$.json "$DATABASE_JSON_FILE"

    echo "$CLIENT Username has Updated in the database file."
	echo
    # Check if the update was successful
    if [ $? -eq 0 ]; then
        echo -e "${CYAN}User $CLIENT updated successfully.${NC}"
    else
        echo -e "${RED}Failed to update user $CLIENT. ${NC}"
    fi
	eXtpause
	manageMenu

}


function newClient() {
	CLIENT=""
	echo ""
	echo -e "${YELLOW}Enter the client's name:${NC}"
	echo "(Must start with a letter and can include letters, numbers, underscores, or hyphens only)"
	echo ""

	until [[ $CLIENT =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ ]]; do
		read -rp "Client Name: " -e CLIENT
	done 

	
	# Check if the user already exists
	if jq -e ".users.$CLIENT" "$DATABASE_JSON_FILE" > /dev/null; then
		echo -e "${CYAN}User $CLIENT already exists. ${NC}"
        exit 1
    fi
	
	# Duplicate the default template for the new user
    jq ".users += {\"$CLIENT\": .users.def_template}" "$DATABASE_JSON_FILE" > temp.json && mv temp.json "$DATABASE_JSON_FILE"

    echo "User $CLIENT has been created with default values into database File."

	echo ""
	echo "Do you want to protect the configuration file with a password?"
	echo "(e.g. encrypt the private key with a password)"
	echo -e "${YELLOW}   1) Add a passwordless client ${NC}"
	echo "   2) Use a password for the client"

	PASS=""
	DEFAULT_OPTION=1

	until [[ $PASS =~ ^[1-2]$ ]]; do
		read -rp "Select an option [1-2]: " -e PASS
		# If no input is given, set PASS to default option
		PASS=${PASS:-$DEFAULT_OPTION}
	done


	CLIENTEXISTS=""
	CLIENTEXISTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c -E "/CN=$CLIENT\$")
	if [[ $CLIENTEXISTS == '1' ]]; then
		echo ""
		echo "The specified client CN was already found in easy-rsa, please choose another name."
		exit
	else
		# Ask for the traffic limit in GB, default is 50
		read -p "Enter the Traffic Limit (default 50): " TRAFFIC_LIMIT
		TRAFFIC_LIMIT=${TRAFFIC_LIMIT:-50}  # Default to 50 if no input	

		# Ask for the expiration date in days, default is 30
		read -p "Enter the expiration period in days (default 30): " EXPIRATION_DAYS
		EXPIRATION_DAYS=${EXPIRATION_DAYS:-30}  # Default to 30 if no input

		# Calculate the expiration date (assuming today's date as the start date)
		EXPIRATION_DATE=$(date -d "+$EXPIRATION_DAYS days" +"%Y-%m-%d")

		# Ask for max IP limit with default value of 2 and range from 0 to 9
		read -p "Enter max IP limit (default 2, range 0-9): " MAX_IP_LIMIT
		MAX_IP_LIMIT=${MAX_IP_LIMIT:-2}

		# Validate max IP limit range
		if ! [[ "$MAX_IP_LIMIT" =~ ^[0-9]$ ]] || [ "$MAX_IP_LIMIT" -gt 9 ]; then
			echo -e "${RED}Invalid input for max IP limit. Must be between 0 and 9. ${NC}"
			exit 1
		fi

		# Ask for the active status (0 for false, 1 for true), default is 1 (active)
		read -p "Is the account active? (0 for No, 1 for Yes, default 1): " ACTIVE
		ACTIVE=${ACTIVE:-1}  # Default to 1 (active) if no input

		# Validate active status input
		if [[ "$ACTIVE" != "0" && "$ACTIVE" != "1" ]]; then
			echo -e "${RED}Invalid input for active status. Must be '0' (inactive) or '1' (active). ${NC}"
			exit 1
		fi

		# Convert numeric input to boolean
		if [[ "$ACTIVE" == "1" ]]; then
			ACTIVE=true
		else
			ACTIVE=false
		fi
		cd /etc/openvpn/easy-rsa/ || return
		case $PASS in
		1)
			EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-client-full "$CLIENT" nopass
			;;
		2)
			echo "You will be asked for the client password below"
			EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-client-full "$CLIENT"
			
			if [ ! -z "$PASS" ]; then
				jq ".users.$CLIENT.password = \"$PASS\"" "$DATABASE_JSON_FILE" > temp.json && mv temp.json "$DATABASE_JSON_FILE"
			fi
			
			;;
		esac
		echo "Client $CLIENT added."
	fi

	# Home directory of the user, where the client configuration will be written
	if [ -e "/root/eXtremePanel/configs/${CLIENT}" ]; then
		# if $1 is a user name
		homeDir="/root/eXtremePanel/configs/${CLIENT}"
	elif [ "${SUDO_USER}" ]; then
		# if not, use SUDO_USER
		if [ "${SUDO_USER}" == "root" ]; then
			# If running sudo as root
			homeDir="/root/eXtremePanel/configs"
		else
			homeDir="/root/eXtremePanel/configs/${SUDO_USER}"
		fi
	else
		# if not SUDO_USER, use /root
		homeDir="/root/eXtremePanel/configs"
	fi
	
	homeDir="/root/eXtremePanel/configs"

	# Determine if we use tls-auth or tls-crypt
	if grep -qs "^tls-crypt" $SERVER_CONFIG_FILE; then
		TLS_SIG="1"
	elif grep -qs "^tls-auth" $SERVER_CONFIG_FILE; then
		TLS_SIG="2"
	fi

	# Generates the custom client.ovpn
	cp $CLIENT_TEMPLATE "$homeDir/$CLIENT.ovpn"
	jq ".users.$CLIENT.vpn_services.openvpn.config_path = \"$homeDir/$CLIENT.ovpn\"" "$DATABASE_JSON_FILE" > temp.json && mv temp.json "$DATABASE_JSON_FILE"
	{
		echo "<ca>"
		cat "/etc/openvpn/easy-rsa/pki/ca.crt"
		echo "</ca>"

		echo "<cert>"
		awk '/BEGIN/,/END CERTIFICATE/' "/etc/openvpn/easy-rsa/pki/issued/$CLIENT.crt"
		echo "</cert>"

		echo "<key>"
		cat "/etc/openvpn/easy-rsa/pki/private/$CLIENT.key"
		echo "</key>"

		case $TLS_SIG in
		1)
			echo "<tls-crypt>"
			cat /etc/openvpn/tls-crypt.key
			echo "</tls-crypt>"
			;;
		2)
			echo "key-direction 1"
			echo "<tls-auth>"
			cat /etc/openvpn/tls-auth.key
			echo "</tls-auth>"
			;;
		esac
	} >>"$homeDir/$CLIENT.ovpn"
	
	jq --arg client "$CLIENT" \
	   --arg exp_date "$EXPIRATION_DATE" \
	   --argjson max_ip "$MAX_IP_LIMIT" \
	   --arg active "$ACTIVE" \
	   --arg password "$USER_PASSWORD" \
	   --argjson data_usage "$TRAFFIC_LIMIT" \
	   --arg last_ip "192.168.0.1" \
	   --argjson zero 0 \
	   --arg wg_last_ip "192.168.0.1" \
	   --arg ovpn_last_ip "192.168.1.1" \
	   '.users[$client] //= {} |
		.users[$client].expiration_date = $exp_date |
		.users[$client].max_ip_limit = $max_ip |
		.users[$client].active = ($active == "true") |
		.users[$client].password = $password |
		.users[$client].data_usage = $data_usage |
		.users[$client].last_ip = $last_ip |
		.users[$client].vpn_services.openvpn.upload_GB = $zero |
		.users[$client].vpn_services.openvpn.download_GB = $zero |
		.users[$client].vpn_services.openvpn.total_usage_GB = $zero |
		.users[$client].vpn_services.openvpn.last_connected_ip = $ovpn_last_ip |
		.users[$client].vpn_services.wireguard.upload_GB = $zero |
		.users[$client].vpn_services.wireguard.download_GB = $zero |
		.users[$client].vpn_services.wireguard.total_usage_GB = $zero |
		.users[$client].vpn_services.wireguard.last_connected_ip = $wg_last_ip |
		.users[$client].total_upload_GB = $zero |
		.users[$client].total_download_GB = $zero |
		.users[$client].total_usage_GB = $zero |
		.users[$client].remaining_data_GB = $data_usage' \
	   "$DATABASE_JSON_FILE" > tmp.$$.json && mv tmp.$$.json "$DATABASE_JSON_FILE"

	echo "Updated $CLIENT information in the JSON file."
	# Check if the update was successful
	if [ $? -eq 0 ]; then
		echo "User $CLIENT updated successfully."
	else
		echo -e "${RED}Failed to update user $CLIENT. ${NC}"
	fi
	
	echo ""
	echo -e "${CYAN}The configuration file has been written to $homeDir/$CLIENT.ovpn. ${NC}"
	echo "Download the .ovpn file and import it in your OpenVPN client."
	echo ""
	echo "-----------------------------------------"
	echo ""
	eXtpause
	manageMenu
}


function revokeClient() {
	CLIENTNUMBER=""
	NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
	if [[ $NUMBEROFCLIENTS == '0' ]]; then
		echo ""
		echo "You have no existing clients!"
		eXtpause
		manageMenu
	fi

	echo ""
	echo "Select the existing client certificate you want to delete"
	echo "Enter 0 to return to the main menu."
	tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
		until [[ $CLIENTNUMBER -ge 0 && $CLIENTNUMBER -le $NUMBEROFCLIENTS ]]; do
		if [[ $CLIENTNUMBER == '1' ]]; then
			read -rp "Select one client [1]: " CLIENTNUMBER
		else
			read -rp "Select one client [0-$NUMBEROFCLIENTS]: " CLIENTNUMBER
		fi
		
		# Check if the user entered 0 to go back to the main menu
		if [[ $CLIENTNUMBER == '0' ]]; then
			manageMenu
			return
		fi
	done
	CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
	cd /etc/openvpn/easy-rsa/ || return
	./easyrsa --batch revoke "$CLIENT"
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	rm -f /etc/openvpn/crl.pem
	cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
	chmod 644 /etc/openvpn/crl.pem
	find /home/ -maxdepth 2 -name "$CLIENT.ovpn" -delete
	rm -f "/root/$CLIENT.ovpn"
	sed -i "/^$CLIENT,.*/d" /etc/openvpn/ipp.txt
	cp /etc/openvpn/easy-rsa/pki/index.txt{,.bk}
	
	if jq -e --arg client "$CLIENT" '.users[$client]' "$DATABASE_JSON_FILE" > /dev/null; then
    # Remove the selected user from the database file
    jq --arg client "$CLIENT" 'del(.users[$client])' "$DATABASE_JSON_FILE" > tmp.$$.json && mv tmp.$$.json "$DATABASE_JSON_FILE"
    
    # Check if the removal was successful
		if [ $? -eq 0 ]; then
			echo "User $CLIENT has been successfully removed."
		else
			echo -e "${RED}Failed to remove user $CLIENT. ${NC}"
		fi
	else
		echo -e "${RED}User $CLIENT does not exist in the database file. ${NC}"
	fi

	echo ""
	echo "Certificate for client $CLIENT revoked."
	eXtpause
	manageMenu	
}

function removeUnbound() {
	# Remove OpenVPN-related config
	sed -i '/include: \/etc\/unbound\/openvpn.conf/d' /etc/unbound/unbound.conf
	rm /etc/unbound/openvpn.conf

	until [[ $REMOVE_UNBOUND =~ (y|n) ]]; do
		echo ""
		echo "If you were already using Unbound before installing OpenVPN, I removed the configuration related to OpenVPN."
		read -rp "Do you want to completely remove Unbound? [y/n]: " -e REMOVE_UNBOUND
	done

	if [[ $REMOVE_UNBOUND == 'y' ]]; then
		# Stop Unbound
		systemctl stop unbound

		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get remove --purge -y unbound
		elif [[ $OS == 'arch' ]]; then
			pacman --noconfirm -R unbound
		elif [[ $OS =~ (centos|amzn|oracle) ]]; then
			yum remove -y unbound
		elif [[ $OS == 'fedora' ]]; then
			dnf remove -y unbound
		fi

		rm -rf /etc/unbound/

		echo ""
		echo "Unbound removed!"
	else
		systemctl restart unbound
		echo ""
		echo "Unbound wasn't removed."
	fi
}

function removeOpenVPN() {
	echo ""
	REMOVE=""
	read -rp "Do you really want to remove OpenVPN? [y/n]: " -e -i n REMOVE
	if [[ $REMOVE == 'y' ]]; then
		# Get OpenVPN port from the configuration
		PORT=$(grep '^port ' $SERVER_CONFIG_FILE | cut -d " " -f 2)
		PROTOCOL=$(grep '^proto ' $SERVER_CONFIG_FILE | cut -d " " -f 2)

		# Stop OpenVPN
		if [[ $OS =~ (fedora|arch|centos|oracle) ]]; then
			systemctl disable openvpn-server@server
			systemctl stop openvpn-server@server
			# Remove customised service
			rm /etc/systemd/system/openvpn-server@.service
		elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
			systemctl disable openvpn
			systemctl stop openvpn
		else
			systemctl disable openvpn@server
			systemctl stop openvpn@server
			# Remove customised service
			rm /etc/systemd/system/openvpn\@.service
		fi

		# Remove the iptables rules related to the script
		systemctl stop iptables-openvpn
		# Cleanup
		systemctl disable iptables-openvpn
		rm /etc/systemd/system/iptables-openvpn.service
		systemctl daemon-reload
		rm /etc/iptables/add-openvpn-rules.sh
		rm /etc/iptables/rm-openvpn-rules.sh

		# SELinux
		if hash sestatus 2>/dev/null; then
			if sestatus | grep "Current mode" | grep -qs "enforcing"; then
				if [[ $PORT != '1194' ]]; then
					semanage port -d -t openvpn_port_t -p "$PROTOCOL" "$PORT"
				fi
			fi
		fi

		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get remove --purge -y openvpn
			if [[ -e /etc/apt/sources.list.d/openvpn.list ]]; then
				rm /etc/apt/sources.list.d/openvpn.list
				apt-get update
			fi
		elif [[ $OS == 'arch' ]]; then
			pacman --noconfirm -R openvpn
		elif [[ $OS =~ (centos|amzn|oracle) ]]; then
			yum remove -y openvpn
		elif [[ $OS == 'fedora' ]]; then
			dnf remove -y openvpn
		fi

		# Cleanup
		find /home/ -maxdepth 2 -name "*.ovpn" -delete
		find /root/ -maxdepth 1 -name "*.ovpn" -delete
		rm -rf /etc/openvpn
		rm -rf /usr/share/doc/openvpn*
		rm -f /etc/sysctl.d/99-openvpn.conf
		rm -rf /var/log/openvpn

		# Unbound
		if [[ -e /etc/unbound/openvpn.conf ]]; then
			removeUnbound
		fi
		echo ""
		echo "OpenVPN removed!"
	else
		echo ""
		echo "Removal aborted!"
	fi
}

############## Function to update domain in the JSON file and OpenVPN client template
# Function to update domain in the JSON file, OpenVPN client template, and .ovpn files
update_openvpn_settings() {
    # Define file paths
    DATABASE_JSON_FILE="/usr/local/etc/eXtremePanel/database/eXtremePanel.json"
    CLIENT_TEMPLATE="/etc/openvpn/client-template.txt"
    OVPN_CONFIGS="/root/eXtremePanel/configs/*.ovpn"

    # Check if JSON file exists
    if [ ! -f "$DATABASE_JSON_FILE" ]; then
        echo "Error: JSON file not found: $DATABASE_JSON_FILE."
        exit 1
    fi

    # Extract current values using jq
    current_domain=$(jq -r '.settings.domain' "$DATABASE_JSON_FILE")
    current_port=$(jq -r '.settings.openVPN_port' "$DATABASE_JSON_FILE")
    current_dns1=$(jq -r '.settings.openVPN_DNS1' "$DATABASE_JSON_FILE")
    current_dns2=$(jq -r '.settings.openVPN_DNS2' "$DATABASE_JSON_FILE")

    # Prompt user for new domain or IP, showing current as default
    read -p "Please enter the domain name or IP address [current: $current_domain]: " new_domain
    new_domain=${new_domain:-$current_domain}  # Use current value if input is empty

    # Prompt user for new OpenVPN port, showing current as default
    read -p "Please enter the OpenVPN port [current: $current_port]: " new_port
    new_port=${new_port:-$current_port}  # Use current value if input is empty

    # Prompt user for new OpenVPN DNS1, showing current as default
    read -p "Please enter the OpenVPN DNS1 [current: $current_dns1]: " new_dns1
    new_dns1=${new_dns1:-$current_dns1}  # Use current value if input is empty

    # Prompt user for new OpenVPN DNS2, showing current as default
    read -p "Please enter the OpenVPN DNS2 [current: $current_dns2]: " new_dns2
    new_dns2=${new_dns2:-$current_dns2}  # Use current value if input is empty

    # Update JSON file with new values
    jq --arg domain "$new_domain" --arg port "$new_port" --arg dns1 "$new_dns1" --arg dns2 "$new_dns2" \
        '.settings.domain = $domain | .settings.openVPN_port = $port | .settings.openVPN_DNS1 = $dns1 | .settings.openVPN_DNS2 = $dns2' \
        "$DATABASE_JSON_FILE" > "${DATABASE_JSON_FILE}.tmp" && mv "${DATABASE_JSON_FILE}.tmp" "$DATABASE_JSON_FILE"
    
    echo "Updated domain, port, and DNS values in $DATABASE_JSON_FILE"

    # Update the OpenVPN client template file if it exists
    if [ -f "$CLIENT_TEMPLATE" ]; then
        # Use sed to update the 'remote' line with the new domain or IP and the correct port
        sed -i "s|^remote .* [0-9]*|remote $new_domain $new_port|" "$CLIENT_TEMPLATE"
        echo "Updated remote address in $CLIENT_TEMPLATE"
    else
        echo "OpenVPN template file not found: $CLIENT_TEMPLATE"
    fi

    # Ask user if they want to update all .ovpn files
    read -p "Do you want to update the new domain name [$new_domain] in all .ovpn files in /root/eXtremePanel/configs? (yes/no): " update_all

    if [[ "$update_all" =~ ^[Yy][Ee][Ss]$ ]]; then
        # Update all .ovpn files with the new domain or IP
        for file in $OVPN_CONFIGS; do
            if [ -f "$file" ]; then
                # Update the remote line in each .ovpn file with the new domain or IP and port
                sed -i "s|^remote .* [0-9]*|remote $new_domain $new_port|" "$file"
                echo "Updated remote address in $file"
            else
                echo "No .ovpn files found in $OVPN_CONFIGS"
            fi
        done
    else
        echo "No changes were made to the .ovpn files."
    fi
}

function installEzWarp() {


#necessary functions 
architecture() {
  case "$(uname -m)" in
    'i386' | 'i686') arch='386' ;;
    'x86_64') arch='amd64' ;;
    'armv5tel') arch='armv5' ;;
    'armv6l') arch='armv6' ;;
    'armv7' | 'armv7l') arch='armv7' ;;
    'aarch64') arch='arm64' ;;
    'mips64el') arch='mips64le_softfloat' ;;
    'mips64') arch='mips64_softfloat' ;;
    'mipsel') arch='mipsle_softfloat' ;;
    'mips') arch='mips_softfloat' ;;
    's390x') arch='s390x' ;;
    *) echo "error: The architecture is not supported."; return 1 ;;
  esac
  echo "$arch"
}

#check user status
if [ "$(id -u)" -ne 0 ]; then
    echo "This script requires root privileges. Please run it as root."
    exit 1
fi
#installing necessary packages

apt update || true
for pkg in wireguard wireguard-dkms wireguard-tools resolvconf; do
    sudo apt install -y $pkg || true
done

#checking packages
if ! command -v wg-quick &> /dev/null
then
    echo "something went wrong with wireguard package installation"
    exit 1
fi
if ! command -v resolvconf &> /dev/null
then
    echo "something went wrong with resolvconf package installation"
    exit 1
fi

clear
#downloading assets
arch=$(architecture)
wget -O "/usr/bin/wgcf" https://github.com/ViRb3/wgcf/releases/download/v2.2.19/wgcf_2.2.19_linux_$arch
chmod +x /usr/bin/wgcf



clear
# removing files that might cause problems

rm -rf wgcf-account.toml &> /dev/null || true
rm -rf /etc/wireguard/warp.conf &> /dev/null || true
# main dish

wgcf register
read -rp "Do you want to use your own key? (Y/n): " response
if [[ $response =~ ^[Yy]$ ]]; then
    read -rp "ENTER YOUR LICENSE: " LICENSE_KEY
    sed -i "s/license_key = '.*'/license_key = '$LICENSE_KEY'/" wgcf-account.toml
    wgcf update
fi

wgcf generate



#creating config in the wireguard directory

# this algorithm is  deprecated

# PRIVATE_KEY=$(grep -oP 'PrivateKey\s*=\s*\K.*' wgcf-profile.conf)
# cat << EOF > "/etc/wireguard/warp.conf"
# [Interface]
# PrivateKey = $PRIVATE_KEY
# Address = 172.16.0.2/32
# Address = 2606:4700:110:8a1a:85ef:da37:b891:8d01/128
# DNS = 1.1.1.1
# MTU = 1280
# Table = off
# [Peer]
# PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
# AllowedIPs = 0.0.0.0/0
# AllowedIPs = ::/0
# Endpoint = engage.cloudflareclient.com:2408
# EOF

# the better algorithm

sed -i '/\[Peer\]/i Table = off' wgcf-profile.conf
mv wgcf-profile.conf /etc/wireguard/warp.conf

systemctl disable --now wg-quick@warp &> /dev/null || true
systemctl enable --now wg-quick@warp

echo "Wireguard warp is up and running"
}

function manageMenu() {
	clear
	MENU_OPTION=""
	echo ""
	echo "eXtreme OpenVPN UI Version:$SCRIPT_VERSION"
	echo ""
	echo "What do you want to do?"
	echo "----------------------------------------------------------------------------------"
	echo "   1) Add a new user                             21- Change OpenVPN Settings."
	echo "   2) Edit existing user                         22- Install ResolveSystem"
	echo "   3) Delete existing user                       23- Install eZ-Warp "
	echo -e "${RED}   99) Uninstall OpenVPN ${NC}"
	echo -e "${YELLOW}   0) Exit${NC}"
	
	# Correct the regex to match 1-99 properly
	until [[ $MENU_OPTION =~ ^[0-9]+$ && $MENU_OPTION -ge 0 && $MENU_OPTION -le 99 ]]; do
		read -rp "Select an option [1-99]: " MENU_OPTION
	done

	case $MENU_OPTION in
	1)
		newClient
		;;
	2)
		userManager
		;;
	3)
		revokeClient
		;;
	21)
		update_openvpn_settings
		;;
	22)
		installResolveService
		;;
	23)
		installEzWarp
		;;
	99)
		removeOpenVPN
		;;
	0)
		exit
		;;
	esac
}


function userManager() {
			
	NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
	if [[ $NUMBEROFCLIENTS == '0' ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi
	
	echo ""
	echo "Select the existing client you want to edit"
	CLIENTNUMBER=""
	tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
	until [[ $CLIENTNUMBER -ge 1 && $CLIENTNUMBER -le $NUMBEROFCLIENTS ]]; do
		if [[ $CLIENTNUMBER == '1' ]]; then
			read -rp "Select one client [1]: " CLIENTNUMBER
		else
			read -rp "Select one client [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
		fi
	done
	
	#Get Client Name
	CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
	clear
	echo ""
	if jq -e --arg client "$CLIENT" '.users[$client]' "$DATABASE_JSON_FILE" > /dev/null; then
		# Extract and display client information using jq
		USER_INFO=$(jq -r --arg client "$CLIENT" '
			.users[$client] |
			"--------------------------------------------------------------------------",
			"Username: \($client)",
			"Password: \(.password // "N/A")",
			"",
			"Active: \(.active)",
			"Max IP Limit: \(.max_ip_limit // "N/A")",
			"Expiration Date: \(.expiration_date // "N/A")",
			"Last IP: \(.last_ip // "N/A")",
			"",
			"Client Traffic: \(.data_usage // "N/A") GB",
			"Total Usage Traffic - [Data Usage: \(.total_usage_GB // 0) GB - Remaining: \(.remaining_data_GB // 0) GB]",
			"",
			"OpenVPN Config Path: \(.vpn_services.openvpn.config_path // "N/A")",
			"OpenVPN Usage Traffic - Download: \(.vpn_services.openvpn.download_GB // 0) GB, Upload: \(.vpn_services.openvpn.upload_GB // 0) GB, Total: \(.vpn_services.openvpn.total_usage_GB // 0) GB",
			"",
			"WireGuard Config Path: \(.vpn_services.wireguard.config_path // "N/A")",
			"WireGuard Usage Traffic - Download: \(.vpn_services.wireguard.download_GB // 0) GB, Upload: \(.vpn_services.wireguard.upload_GB // 0) GB, Total: \(.vpn_services.wireguard.total_usage_GB // 0) GB"
		' "$DATABASE_JSON_FILE")

		echo -e "$USER_INFO"
	else
		echo -e "${RED}User $CLIENT does not exist in the database file.${NC}"
	fi
	
	echo ""
	echo "--------------------------------------------------------------------------"
	

################### edit user menu
	
	# Display menu options
	echo ""
	echo "1- Select another account"
	echo "2- Edit current account"
	echo "00- Back to menu"
	echo ""

	# Prompt for the user's choice
	read -p "Select an option: " SEC_OPTION

	case $SEC_OPTION in
		1)
			# Loop will restart to select another account
			userManager
			;;
		2)
			# Call a function or script to edit the current account (placeholder for edit functionality)
			editClient
			;;
		00)
			echo "Returning to main menu..."
			manageMenu
			;;
		*)
			echo "Invalid option, please select 01, 02, or 00."
			userManager
			;;
	esac

}

# Check for root, TUN, OS...
initialCheck

# Check if OpenVPN is already installed
if [[ -e $SERVER_CONFIG_FILE && $AUTO_INSTALL != "y" ]]; then
	manageMenu
else
	installOpenVPN
	TARGET_DIR="/usr/local/etc/eXtremePanel/eXtremePanel"
	wget -O /tmp/script.sh "$SCRIPT_URL_ADDRESS"
	if [ $? -ne 0 ]; then
	  echo "Failed to download the script."
	  exit 1
	fi
	mkdir -p "$TARGET_DIR"
	cp /tmp/script.sh "$TARGET_DIR"
	chmod +x "$TARGET_DIR/script.sh"

	echo "execute eXtremePanel command to run eXtremePanel."
fi
