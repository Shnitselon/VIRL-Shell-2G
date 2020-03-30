#!/usr/bin/python
# -*- coding: utf-8 -*-

__all__ = ["IOSv", "NX_OSv"]


class Port:
    Port = """
    interface GigabitEthernet0/{id}
      description {description}
      ip address {address} {netmask}
      cdp enable
      duplex full
      speed auto
      no shutdown
    """

    def __init__(self, ifaces):
        self.ifaces = ifaces

    def build_ports(self):

        ports = "!".join([self.Port.format(id=int(iface.id) + 1,
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
    username {user} privileges 15 secret {password}
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
                                    snmp_community=self.node.snmp_community,
                                    interfaces=ports)
        return config


class NX_OSv:
    CONFIG = """
    service timestamps debug datetime msec
    service timestamps log datetime msec
    hostname {node_name}
    !
    boot-start-marker
    boot-end-marker
    !
    username {user} privileges 15 secret {password}
    enable password {enable_password}
    no service password-encryption
    no service config
    !
    ip ssh version 2
    ip ssh server algorithm authentication password
    ip scp server enable
    !
    snmp-server chassis-id 
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
                                    interfaces=ports)
        return config


if __name__ == "__main__":
    pass
