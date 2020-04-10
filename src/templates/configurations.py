#!/usr/bin/python
# -*- coding: utf-8 -*-

__all__ = ["IOSv", "IOSvL2",
           "NX_OSv", "NX_OSv_9000",
           "IOS_XRv", "IOS_XRv_9000",
           "CSR1000v", "ASAv"
           ]


class Port:
    PORT = """
    interface GigabitEthernet0/{id}
      description {description}
      ip address {address} {netmask}
      cdp enable
      duplex full
      speed auto
      no shutdown
    """

    def __init__(self, ifaces, port_template=None, port_id_start=1):
        self.ifaces = ifaces
        self.port_template = port_template or self.PORT
        self.port_id_start = port_id_start

    def build_ports(self):
        ports = "!".join([self.port_template.format(id=int(iface.id) + self.port_id_start,
                                                    address=iface.address,
                                                    netmask=iface.netmask,
                                                    description=iface.description) for iface in self.ifaces])

        return ports


class IOSv:
    CONFIG = """
    service timestamps debug datetime msec
    service timestamps log datetime msec
    hostname {node_name}
    !
    boot-start-marker
    boot-end-marker
    !
    aaa new-model
    ip domain name virl.info
    crypto key generate rsa modulus 2048
    username {user} privilege 15 secret {password}
    enable password {enable_password}
    no service password-encryption
    no service config
    !
    ip ssh version 2
    ip ssh server algorithm authentication password
    ip scp server enable
    !
    snmp-server chassis-id
    snmp-server community {snmp_community} RO
    !
    interface GigabitEthernet0/0
      no switchport
      ip address dhcp
      duplex auto
      speed auto
      media-type rj45
      no shutdown
    !{interfaces}!
    !
    line vty 0 4
      login    
      transport input ssh telnet
    !
    end
    """

    def __init__(self, node):
        self.node = node

    def config_builder(self):
        """ Build configuration for specific device """

        ports = Port(ifaces=self.node.ifaces).build_ports()

        config = self.CONFIG.format(node_name=self.node.name,
                                    user=self.node.user,
                                    password=self.node.password,
                                    enable_password=self.node.en_password,
                                    default_gateway=self.node.default_gateway,
                                    address=self.node.address,
                                    netmask=self.node.netmask,
                                    snmp_community=self.node.snmp_community,
                                    interfaces=ports)
        return config


class IOSvL2:
    PORT = """
    interface GigabitEthernet0/{id}
     description {description}
     switchport mode trunk
     media-type rj45
     negotiation auto
    """

    CONFIG = """
    service timestamps debug datetime msec
    service timestamps log datetime msec
    no service password-encryption
    service compress-config
    !
    hostname {node_name}
    !
    boot-start-marker
    boot-end-marker
    !
    aaa new-model
    ip domain name virl.info
    crypto key generate rsa modulus 2048
    username {user} privilege 15 secret {password}
    enable password {enable_password}
    no service password-encryption
    no service config
    !
    aaa session-id common
    !
    vtp domain virl.lab
    vtp mode transparent
    !
    no ip domain-lookup
    ip cef
    no ipv6 cef
    !
    ip forward-protocol nd
    !
    no ip http server
    !
    ip route 0.0.0.0 0.0.0.0 {default_gateway}
    ip ssh server algorithm encryption aes128-ctr aes192-ctr aes256-ctr
    ip ssh client algorithm encryption aes128-ctr aes192-ctr aes256-ctr
    !
    control-plane
    !
    spanning-tree mode pvst
    spanning-tree extend system-id
    !
    interface Loopback0
     description Loopback
     no ip address
    !
    interface GigabitEthernet0/0
     description OOB management
     no switchport
     ip address dhcp
     speed 1000
     duplex full
     no negotiation auto
    !
    !{interfaces}!
    !
    line vty 0 4
      login    
      transport input ssh telnet
    !
    end
    """

    def __init__(self, node):
        self.node = node

    def config_builder(self):
        """ Build configuration for specific device """

        ports = Port(ifaces=self.node.ifaces, port_template=self.PORT).build_ports()

        config = self.CONFIG.format(node_name=self.node.name,
                                    user=self.node.user,
                                    password=self.node.password,
                                    enable_password=self.node.en_password,
                                    default_gateway=self.node.default_gateway,
                                    address=self.node.address,
                                    netmask=self.node.netmask,
                                    snmp_community=self.node.snmp_community,
                                    interfaces=ports)
        return config


class NX_OSv:
    PORT = """
    interface Ethernet2/{id}
      description {description}
      ip address {address} {netmask}
      switchport
      no shutdown
    """

    CONFIG = """
    hostname {node_name}
    vdc {node_name} id 1
      limit-resource vlan minimum 16 maximum 4094
      limit-resource vrf minimum 2 maximum 4096
      limit-resource port-channel minimum 0 maximum 768
      limit-resource u4route-mem minimum 96 maximum 96
      limit-resource u6route-mem minimum 24 maximum 24
    
    feature telnet
    feature ospf
    
    username {user} password {password} role network-admin
    no password strength-check
    ip domain-lookup
    copp profile strict
    rmon event 1 log trap public description FATAL(1) owner PMON@FATAL
    rmon event 2 log trap public description CRITICAL(2) owner PMON@CRITICAL
    rmon event 3 log trap public description ERROR(3) owner PMON@ERROR
    rmon event 4 log trap public description WARNING(4) owner PMON@WARNING
    rmon event 5 log trap public description INFORMATION(5) owner PMON@INFO
    
    vlan 1
    
    vrf context management
      ip route 0.0.0.0 0.0.0.0 {default_gateway}
    
    hardware forwarding unicast trace
    
    interface Loopback0
      description Loopback
      ip address 192.168.0.1/32
      ip router ospf 1 area 0
    
    interface mgmt0
      description OOB Management
      ! Configured on launch
      no ip address
      duplex full
      no shutdown
      vrf member management

    {interfaces}
    
    line console
    line vty
    router ospf 1
      router-id 192.168.0.1
    """

    def __init__(self, node):
        self.node = node

    def config_builder(self):
        """ Build configuration for specific device """

        ports = Port(ifaces=self.node.ifaces, port_template=self.PORT).build_ports()

        config = self.CONFIG.format(node_name=self.node.name,
                                    user=self.node.user,
                                    password=self.node.password,
                                    enable_password=self.node.en_password,
                                    default_gateway=self.node.default_gateway,
                                    address=self.node.address,
                                    netmask=self.node.netmask,
                                    snmp_community=self.node.snmp_community,
                                    interfaces=ports)
        return config


class NX_OSv_9000:
    PORT = """
    interface Ethernet1/{id}
      description {description}
      no switchport
      ip address {address} {netmask}
      ip router ospf 1 area 0.0.0.0
      no shutdown
    """

    CONFIG = """
    hostname {node_name}
    vdc {node_name} id 1
      limit-resource vlan minimum 16 maximum 4094
      limit-resource vrf minimum 2 maximum 4096
      limit-resource port-channel minimum 0 maximum 511
      limit-resource u4route-mem minimum 96 maximum 96
      limit-resource u6route-mem minimum 24 maximum 24
      limit-resource m4route-mem minimum 58 maximum 58
      limit-resource m6route-mem minimum 8 maximum 8
    
    feature telnet
    feature ospf
    
    no password strength-check
    username admin password 5 $1$KuOSBsvW$Cy0TSD..gEBGBPjzpDgf51 role network-admin
    ip domain-lookup
    rmon event 1 log trap public description FATAL(1) owner PMON@FATAL
    rmon event 2 log trap public description CRITICAL(2) owner PMON@CRITICAL
    rmon event 3 log trap public description ERROR(3) owner PMON@ERROR
    rmon event 4 log trap public description WARNING(4) owner PMON@WARNING
    rmon event 5 log trap public description INFORMATION(5) owner PMON@INFO
    
    copp profile strict
    
    vlan 1
    
    vrf context management

    hardware forwarding unicast trace

    interface loopback0
      description Loopback
      ip address 192.168.0.5/32
      ip router ospf 1 area 0.0.0.0
    
    interface mgmt0
      description OOB Management
      ip address dhcp
      duplex full
      no shutdown
      vrf member management
    
    {interfaces}
    
    line console
    line vty
    router ospf 1
      router-id 192.168.0.5
    
    username {user} password {password} role network-admin
    """

    def __init__(self, node):
        self.node = node

    def config_builder(self):
        """ Build configuration for specific device """

        ports = Port(ifaces=self.node.ifaces, port_template=self.PORT).build_ports()

        config = self.CONFIG.format(node_name=self.node.name,
                                    user=self.node.user,
                                    password=self.node.password,
                                    enable_password=self.node.en_password,
                                    default_gateway=self.node.default_gateway,
                                    address=self.node.address,
                                    netmask=self.node.netmask,
                                    snmp_community=self.node.snmp_community,
                                    interfaces=ports)
        return config


class IOS_XRv:
    CONFIG = """"""


class IOS_XRv_9000:
    PORT = """
    interface GigabitEthernet0/0/0/{id}
      description {description}
      ipv4 address {address} {netmask}
      no shutdown
    """

    CONFIG = """
    hostname {node_name}
    !
    username {user}
      group root-lr
      group cisco-support
      secret {password}
    !
    call-home
      service active
      contact smart-licensing
      profile CiscoTAC-1
        active
        destination transport-method http
    !
    interface MgmtEth0/RP0/CPU0/0
      ipv4 address dhcp
    !
    !{interfaces}!
    !
    ssh server v2
    end
    """

    def __init__(self, node):
        self.node = node

    def config_builder(self):
        """ Build configuration for specific device """

        ports = Port(ifaces=self.node.ifaces, port_template=self.PORT).build_ports()

        config = self.CONFIG.format(node_name=self.node.name,
                                    user=self.node.user,
                                    password=self.node.password,
                                    enable_password=self.node.en_password,
                                    default_gateway=self.node.default_gateway,
                                    address=self.node.address,
                                    netmask=self.node.netmask,
                                    snmp_community=self.node.snmp_community,
                                    interfaces=ports)
        return config


class CSR1000v:
    PORT = """
    interface GigabitEthernet{id}
     description {description}
     ip address {address} {netmask}
     no shutdown
     negotiation auto
     no mop enabled
     no mop sysid
    """

    CONFIG = """
    service timestamps debug datetime msec
    service timestamps log datetime msec
    platform qfp utilization monitor load 80
    no platform punt-keepalive disable-kernel-core
    platform console serial
    !
    hostname {node_name}
    boot-start-marker
    boot-end-marker
    !
    vrf definition management
     address-family ipv4
     exit-address-family
     !
     address-family ipv6
     exit-address-family
    !
    aaa new-model
    ip domain name virl.info
    crypto key generate rsa modulus 2048
    username {user} privilege 15 secret {password}
    enable password {enable_password}
    no service password-encryption
    no service config
    !
    interface GigabitEthernet1
      description OOB Management
      vrf forwarding management
      ip address dhcp
      no shutdown
    !
    !{interfaces}!
    !
    line vty 0 4
     transport input ssh telnet
    !
    end
    """

    def __init__(self, node):
        self.node = node

    def config_builder(self):
        """ Build configuration for specific device """

        ports = Port(ifaces=self.node.ifaces, port_template=self.PORT, port_id_start=2).build_ports()

        config = self.CONFIG.format(node_name=self.node.name,
                                    user=self.node.user,
                                    password=self.node.password,
                                    enable_password=self.node.en_password,
                                    default_gateway=self.node.default_gateway,
                                    address=self.node.address,
                                    netmask=self.node.netmask,
                                    snmp_community=self.node.snmp_community,
                                    interfaces=ports)
        return config


class ASAv:
    PORT = """
    interface GigabitEthernet0/{id}
     description {description}
     duplex full
     nameif outside-{id}
     security-level 0
     ip address {address} {netmask}
    """

    CONFIG = """
    hostname {node_name}
    xlate per-session deny tcp any4 any4
    xlate per-session deny tcp any4 any6
    xlate per-session deny tcp any6 any4
    xlate per-session deny tcp any6 any6
    xlate per-session deny udp any4 any4 eq domain
    xlate per-session deny udp any4 any6 eq domain
    xlate per-session deny udp any6 any4 eq domain
    xlate per-session deny udp any6 any6 eq domain
    !
    interface Management0/0
     description OOB Management
     duplex full
     management-only
     nameif mgmt
     security-level 100
     ip address dhcp
    !
    !{interfaces}
    !
    ftp mode passive
    same-security-traffic permit inter-interface
    pager lines 23
    logging enable
    logging asdm informational
    mtu mgmt 1500
    no failover
    no monitor-interface service-module 
    icmp unreachable rate-limit 1 burst-size 1
    no asdm history enable
    arp timeout 14400
    no arp permit-nonconnected
    arp rate-limit 8192
    timeout xlate 3:00:00
    timeout pat-xlate 0:00:30
    timeout conn 1:00:00 half-closed 0:10:00 udp 0:02:00 sctp 0:02:00 icmp 0:00:02
    timeout sunrpc 0:10:00 h323 0:05:00 h225 1:00:00 mgcp 0:05:00 mgcp-pat 0:05:00
    timeout sip 0:30:00 sip_media 0:02:00 sip-invite 0:03:00 sip-disconnect 0:02:00
    timeout sip-provisional-media 0:02:00 uauth 0:05:00 absolute
    timeout tcp-proxy-reassembly 0:01:00
    timeout floating-conn 0:00:00
    timeout conn-holddown 0:00:15
    timeout igp stale-route 0:01:10
    user-identity default-domain LOCAL
    aaa authentication ssh console LOCAL 
    aaa authentication login-history
    no snmp-server location
    no snmp-server contact
    crypto ipsec security-association pmtu-aging infinite
    telnet 0.0.0.0 0.0.0.0 mgmt
    telnet timeout 15
    ssh stricthostkeycheck
    ssh 0.0.0.0 0.0.0.0 mgmt
    ssh timeout 5
    ssh version 2
    ssh key-exchange group dh-group1-sha1
    console timeout 0
    console serial
    threat-detection basic-threat
    threat-detection statistics access-list
    no threat-detection statistics tcp-intercept
    dynamic-access-policy-record DfltAccessPolicy
    !
    aaa new-model
    ip domain name virl.info
    crypto key generate rsa modulus 2048
    username {user} privilege 15 secret {password}
    enable password {enable_password}
    no service password-encryption
    no service config
    !
    class-map inspection_default
     match default-inspection-traffic
    !
    policy-map type inspect dns preset_dns_map
     parameters
      message-length maximum client auto
      message-length maximum 512
      no tcp-inspection
    policy-map global_policy
     class inspection_default
      inspect ip-options 
      inspect netbios 
      inspect rtsp 
      inspect sunrpc 
      inspect tftp 
      inspect xdmcp 
      inspect icmp 
      inspect http 
      inspect dns preset_dns_map 
      inspect ftp 
      inspect h323 h225 
      inspect h323 ras 
      inspect rsh 
      inspect esmtp 
      inspect sqlnet 
      inspect sip  
      inspect skinny  
    policy-map type inspect dns migrated_dns_map_2
     parameters
      message-length maximum client auto
      message-length maximum 512
      no tcp-inspection
    policy-map type inspect dns migrated_dns_map_1
     parameters
      message-length maximum client auto
      message-length maximum 512
      no tcp-inspection
    !
    service-policy global_policy global
    prompt hostname context 
    no call-home reporting anonymous
    call-home
     profile CiscoTAC-1
      no active
      destination address http https://tools.cisco.com/its/service/oddce/services/DDCEService
      destination address email callhome@cisco.com
     profile License
      destination address http https://tools.cisco.com/its/service/oddce/services/DDCEService
      destination transport-method http
    """

    def __init__(self, node):
        self.node = node

    def config_builder(self):
        """ Build configuration for specific device """

        ports = Port(ifaces=self.node.ifaces, port_template=self.PORT).build_ports()

        config = self.CONFIG.format(node_name=self.node.name,
                                    user=self.node.user,
                                    password=self.node.password,
                                    enable_password=self.node.en_password,
                                    default_gateway=self.node.default_gateway,
                                    address=self.node.address,
                                    netmask=self.node.netmask,
                                    snmp_community=self.node.snmp_community,
                                    interfaces=ports)
        return config


if __name__ == "__main__":
    pass
