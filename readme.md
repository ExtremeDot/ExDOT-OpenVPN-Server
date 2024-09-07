### OpenVPN Server with usermanagment

##### This is a persoanl project and based on Angristan work

*ScreenShot
![image](https://github.com/user-attachments/assets/23a86619-fbc5-4325-af13-ee8d1af2c382)


----
### Install

```
bash -c "$(curl -H 'Cache-Control: no-cache' -L https://raw.githubusercontent.com/ExtremeDot/eXtremePanel/master/extPanel.sh )"
```

##### After installing you can execute "eXtPanel" command to run script.

```
eXtPanel
```
----

### Need Tunneling?

##### Tunneling Between Domestic and Non-Restricted Servers guides
  -you can use below methods
  
  ```
  https://github.com/Azumi67/FRP-Wireguard
  ```

  ```
  https://github.com/Azumi67/Rathole_reverseTunnel
  ```

  ```
  https://github.com/Azumi67/FRP_Reverse_Loadbalance
  ```

  ```
  https://github.com/Azumi67/PrivateIP_TCP-UDP_Tunnel
  ```
----

### Guides

##### REVERSE FRP KCP Tunnel GUIDE

###### Domestic VPS [RESTRICTED] as Server

```
apt install python3 -y && apt install wget -y && sudo apt install python3-pip &&  pip install colorama && pip install netifaces && apt install curl -y && python3 <(curl -Ls https://raw.githubusercontent.com/Azumi67/FRP_Reverse_Loadbalance/main/loadbalance.py --ipv4)
```
![image](https://github.com/user-attachments/assets/6d2c5561-9a76-487d-9c2e-51bc81b16543)

```
2. Installation
```

```
4. FRP KCP Tunnel
```
![image](https://github.com/user-attachments/assets/0cad53bf-67e7-41aa-8b5a-d79fb34018eb)

```
1. IRAN
```
![image](https://github.com/user-attachments/assets/0f861413-2990-4a70-9855-c16f707a98aa)


```
Enter the local ports : 1194
Enter the remote ports : 1194
Enter KCP Port: 12348
Enter Loadbalance Port: 48321
```
* - lcoal ports and remote ports must be defined as the openvpn server on non-restricted vps server
 
-------

###### International  VPS [NON-RESTRICTED] - Open-VPN Server Installed VPS

```
apt install python3 -y && apt install wget -y && sudo apt install python3-pip &&  pip install colorama && pip install netifaces && apt install curl -y && python3 <(curl -Ls https://raw.githubusercontent.com/Azumi67/FRP_Reverse_Loadbalance/main/loadbalance.py --ipv4)
```

```
2. Installation
```

```
4. FRP KCP Tunnel
```

```
2. Kharej [1]
```

```
Enter the number of loadbalance groups [For each different port, there should be a group]: 1
```

```
Enter IRAN IPV4/IPv6 address:
```
Enter IRAN VPS ipv4 or IPV6 port.

```
Enter KCP port : 12348
```

```
Enter Loadbalance Port: 48321
```

```
Enter the starting v2ray and group number: 1
```

```
Enter the Local Port for Loadbalance Group 1: 1194
```

```
Enter the Remote Port for Loadbalance Group 1: 1194
```

---
now get the .ovpn config and change the server address to your domestic vps in ovpn file and run it.
