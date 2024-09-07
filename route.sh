#!/bin/bash
ROUTE_VERSION=1.0
# Define color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo 
echo -e "${YELLOW} eXtreme Panel - routing Interface throug Interface ---[Version: $ROUTE_VERSION]${NC}"

# Function to install a package if it is not installed
install_package() {
    package_name=$1
    if ! dpkg -l | grep -q "^ii  $package_name"; then
        echo -e "${YELLOW}$package_name is not installed. Installing...${NC}"
        sudo apt-get update
        sudo apt-get install -y $package_name
        if [ $? -ne 0 ]; then
            echo -e "${RED}Failed to install $package_name. Please install it manually.${NC}"
            exit 1
        fi
    else
        echo -e "${GREEN}$package_name is already installed.${NC}"
    fi
}

# Check and install net-tools and iptables if not installed
install_package net-tools
install_package iptables

# Enable IP forwarding
echo -e "${CYAN}Enabling IP forwarding...${NC}"
sudo sysctl -w net.ipv4.ip_forward=1
sleep 1
sudo sysctl -p


# Function to get the subnet of an interface
get_subnet() {
    local iface="$1"
    local ip_info
    ip_info=$(ip addr show "$iface" | grep 'inet ' | awk '{print $2}')

    if [[ -n $ip_info ]]; then
        local ip_cidr
        ip_cidr=$(echo "$ip_info" | cut -d'/' -f1)
        local cidr
        cidr=$(echo "$ip_info" | cut -d'/' -f2)

        # Convert CIDR to subnet mask
        local mask
        mask=$(printf "%d.%d.%d.%d\n" $((0xFFFFFFFF << (32 - cidr) >> 24 & 0xFF)) $((0xFFFFFFFF << (32 - cidr) >> 16 & 0xFF)) $((0xFFFFFFFF << (32 - cidr) >> 8 & 0xFF)) $((0xFFFFFFFF << (32 - cidr) & 0xFF)))
        
        # Compute the network address
        local ip_int
        ip_int=$(echo "$ip_cidr" | awk -F'.' '{print ($1 * 256^3) + ($2 * 256^2) + ($3 * 256) + $4}')
        local mask_int
        mask_int=$(echo "$mask" | awk -F'.' '{print ($1 * 256^3) + ($2 * 256^2) + ($3 * 256) + $4}')
        local network_int
        network_int=$((ip_int & mask_int))
        local network
        network=$(printf "%d.%d.%d.%d\n" $((network_int >> 24 & 0xFF)) $((network_int >> 16 & 0xFF)) $((network_int >> 8 & 0xFF)) $((network_int & 0xFF)))

        echo "$network/$cidr"
    else
        echo "No IP info found"
    fi
}

# Function to get the IP address of an interface
get_ip() {
    local iface="$1"
    local ip_info
    ip_info=$(ip addr show "$iface" | grep 'inet ' | awk '{print $2}')
    
    if [[ -n $ip_info ]]; then
        echo "$ip_info" | cut -d'/' -f1
    else
        echo "No IP info found"
    fi
}

# Function to adjust the subnet mask
adjust_subnet() {
    local subnet="$1"
    local ip="${subnet%/*}"
    local cidr="${subnet#*/}"

    if [[ $cidr -eq 32 ]]; then
        # For /32, assume /24 or other common subnet sizes based on your requirements
        local base_ip
        base_ip=$(echo "$ip" | awk -F'.' '{print $1 "." $2 "." $3 ".0"}')
        echo "$base_ip/24"
    else
        echo "$subnet"
    fi
}

# List all interfaces except lo
echo "---------------------------------------------------------"
echo -e "${YELLOW}Select [VPN SERVER] Network Interface:${NC}"
interfaces=($(ip link show | awk -F': ' '{print $2}' | grep -v '^lo'))
select iface in "${interfaces[@]}"; do
    if [[ -n $iface ]]; then
        vpn_subnet=$(get_subnet "$iface")
        break
    else
        echo -e "${RED}Invalid selection. Please try again.${NC}"
    fi
done

echo
echo "---------------------------------------------------------"
# List all interfaces except lo and the selected VPN server interface
echo -e "${YELLOW}Select [DESTINATION] Network Interface:${NC}"
interfaces=($(ip link show | awk -F': ' '{print $2}' | grep -v '^lo' | grep -v "$iface"))
select route_iface in "${interfaces[@]}"; do
    if [[ -n $route_iface ]]; then
        route_subnet=$(get_subnet "$route_iface")
        route_ip=$(get_ip "$route_iface")
        subnet=$(adjust_subnet "$route_subnet")
        break
    else
        echo -e "${RED}Invalid selection. Please try again.${NC}"
    fi
done

### Total Vars
interfaceVPNserver=$iface
subnetVPNserver=$vpn_subnet
subnetDestination=$subnet
ipDestination=$route_ip
interfaceDestination=$route_iface

# Ask user to enter table number
echo
echo "---------------------------------------------------------"
echo -e "${YELLOW}Enter the [TABLE Name]:${NC}"
read -p "Enter number (e.g., 1000): " table_number

echo "----------VPN SERVER-------------"
echo -e "${YELLOW}Selected VPN Server Interface:${NC} $interfaceVPNserver"
echo -e "${YELLOW}Subnet:${NC} $(adjust_subnet "$subnetVPNserver")"
echo 
echo "---------DESTINATION-------------"
echo -e "${YELLOW}Selected Routing Interface:${NC} $interfaceDestination"
echo -e "${YELLOW}Subnet:${NC} ${subnetDestination}"
echo -e "${YELLOW}IP:${NC} $ipDestination"
echo
echo "--------ROUTING TABLE------------"
echo -e "${YELLOW}TABLE:${NC} $table_number"

# Create routing table commands
echo -e "${CYAN}Creating routing table entries...${NC}"
echo "1"
/sbin/ip route add $subnetVPNserver dev $interfaceVPNserver table $table_number
echo "2"
/sbin/ip route add $subnetDestination dev $interfaceDestination table $table_number
echo "3"
/sbin/ip route add default via $ipDestination dev $interfaceDestination table $table_number

# Create IP rules
echo -e "${CYAN}Creating IP rules...${NC}"
echo "4"
/sbin/ip rule add iif $interfaceDestination lookup $table_number

echo "5"
/sbin/ip rule add iif $interfaceVPNserver lookup $table_number

# Configure iptables for NAT
echo -e "${CYAN}Configuring iptables for NAT...${NC}"
echo "6"
/sbin/iptables -t nat -A POSTROUTING -s $subnetVPNserver -o $interfaceDestination -j MASQUERADE

##########
mkdir -p /usr/local/etc/eXtremePanel/database/

echo "Writing wg_${interfaceDestination}_up.sh file."
cat << EOF > /usr/local/etc/eXtremePanel/database/wg_${interfaceDestination}_up.sh
#!/bin/bash

# Assign variables
interfaceVPNserver=$iface
subnetVPNserver=$vpn_subnet
subnetDestination=$subnet
ipDestination=$route_ip
interfaceDestination=$route_iface
TABLE=$table_number
NAT_TABLE="nat"
CHAIN="POSTROUTING"
VPS_DEFAULT_INTERFACE=$(/sbin/ip route | awk '/default/ {print $5}')

# REMOVE DEFAULT ROUTE FOR VPN SERVER
RULE_NUMBER=$(/sbin/iptables -t \$NAT_TABLE -L \$CHAIN -v -n --line-numbers | \
              awk -v src="\$subnetVPNserver" -v out="\$VPS_DEFAULT_INTERFACE" \
              '$0 ~ src && $0 ~ out && $0 ~ "MASQUERADE" {print $1}')

if [ -n "\$RULE_NUMBER" ]; then
	/sbin/iptables -t \$NAT_TABLE -D \$CHAIN \$RULE_NUMBER
fi


# Add routes and rules
/sbin/ip route add \$subnetVPNserver dev \$interfaceVPNserver table \$TABLE
/sbin/ip route add \$subnetDestination dev \$interfaceDestination table \$TABLE
/sbin/ip route add default via \$ipDestination dev \$interfaceDestination table \$TABLE
/sbin/ip rule add iif \$interfaceDestination lookup \$TABLE
/sbin/ip rule add iif \$interfaceVPNserver lookup \$TABLE

# Apply NAT
/sbin/iptables -t nat -A POSTROUTING -s \$subnetVPNserver -o \$interfaceDestination -j MASQUERADE

EOF

#########
echo "Writing wg_${interfaceDestination}_down.sh file."
cat << EOF > /usr/local/etc/eXtremePanel/database/wg_${interfaceDestination}_down.sh
#!/bin/bash

# Assign variables
interfaceVPNserver=$iface
subnetVPNserver=$vpn_subnet
subnetDestination=$subnet
ipDestination=$route_ip
interfaceDestination=$route_iface
TABLE=$table_number

# Add routes and rules
/sbin/ip route del \$subnetVPNserver dev \$interfaceVPNserver table \$TABLE
/sbin/ip route del \$subnetDestination dev \$interfaceDestination table \$TABLE
/sbin/ip route del default via \$ipDestination dev \$interfaceDestination table \$TABLE
/sbin/ip rule del iif \$interfaceDestination lookup \$TABLE
/sbin/ip rule del iif \$interfaceVPNserver lookup \$TABLE

# Apply NAT
/sbin/iptables -t nat -D POSTROUTING -s \$subnetVPNserver -o \$interfaceDestination -j MASQUERADE
EOF

#######
chmod +x /usr/local/etc/eXtremePanel/database/wg_${interfaceDestination}_down.sh
chmod +x /usr/local/etc/eXtremePanel/database/wg_${interfaceDestination}_up.sh

read -p "Do you want to add the PostUp and PreDown scripts to a WireGuard config file? (yes/no): " add_scripts

if [[ "$add_scripts" == "yes" ]]; then
    # List available .conf files in /etc/wireguard/
    config_files=($(ls /etc/wireguard/*.conf 2>/dev/null))
    
    if [ ${#config_files[@]} -eq 0 ]; then
        echo "No WireGuard configuration files found in /etc/wireguard/."
        exit 1
    fi

    echo "Available WireGuard configuration files:"
    for i in "${!config_files[@]}"; do
        echo "$((i+1)). ${config_files[$i]}"
    done

    read -p "Select a configuration file by number: " selected_number

    if ! [[ "$selected_number" =~ ^[0-9]+$ ]] || [ "$selected_number" -lt 1 ] || [ "$selected_number" -gt ${#config_files[@]} ]; then
        echo "Invalid selection. Exiting."
        exit 1
    fi

    selected_config="${config_files[$((selected_number-1))]}"
    
    awk -v up_script="/usr/local/etc/eXtremePanel/database/wg_${interfaceDestination}_up.sh" \
        -v down_script="/usr/local/etc/eXtremePanel/database/wg_${interfaceDestination}_down.sh" \
        'BEGIN { added=0 }
         /^\[Peer\]/ && !added { 
             print "PostUp = " up_script; 
             print "PreDown = " down_script; 
             added=1 
         } 
         { print }' "$selected_config" > /tmp/wg_temp.conf && mv /tmp/wg_temp.conf "$selected_config"

    echo "PostUp and PreDown scripts added to $selected_config."
else
    echo "No changes made to WireGuard configuration files."
fi

echo "Finished"
