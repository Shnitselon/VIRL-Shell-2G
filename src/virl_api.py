#!/usr/bin/python
# -*- coding: utf-8 -*-

import re
import requests
import time

from virl_exceptions import VIRLAPIException

IFACE_REBOOT_TIMEOUT = 3


class VIRL_API:
    def __init__(self, host, std_port=19399, uwm_port=19400, username="guest", password="guest"):
        self.host = host
        self.std_port = std_port
        self.uwm_port = uwm_port
        self.username = username
        self.password = password

    def health_check(self):
        """ Verify VIRL connection possibility """

        url = "http://{host}:{port}/simengine/rest/health".format(host=self.host, port=self.std_port)
        response = requests.request("GET", url, auth=(self.username, self.password))
        response.raise_for_status()
        # print(response.text)

    def upload_topology(self, topology_data, reservation_id):
        """ Upload topology to VIRL Server """

        url = "http://{host}:{port}/simengine/rest/launch".format(host=self.host, port=self.std_port)

        params = {"session": reservation_id}

        response = requests.request("POST", url, data=topology_data, params=params, auth=(self.username, self.password))
        response.raise_for_status()
        # print(response.text)

    def get_topologies_list(self):
        """ Get list of created simulations on VIRL Server """

        url = "http://{host}:{port}/simengine/rest/list".format(host=self.host, port=self.std_port)

        response = requests.request("GET", url, auth=(self.username, self.password))
        response.raise_for_status()
        # print(response.text)

        result = {}
        for topology_name, params in response.json().get("simulations", {}).items():
            result.update({topology_name: params.get("status")})
        return result

    def stop_topology(self, topology_name):
        """ Stop simulation on VIRL Server """

        url = "http://{host}:{port}/simengine/rest/stop/{topology_name}".format(host=self.host,
                                                                                port=self.std_port,
                                                                                topology_name=topology_name)

        response = requests.request("GET", url, auth=(self.username, self.password))
        response.raise_for_status()
        # print(response.text)

    def start_node(self, topology_name, node_name):
        """ Power On VIRL node """

        url = "http://{host}:{port}/simengine/rest/update/{simulation}/start?nodes={node}".format(host=self.host,
                                                                                                  port=self.std_port,
                                                                                                  simulation=topology_name,
                                                                                                  node=node_name)
        response = requests.request("PUT", url, auth=(self.username, self.password))
        response.raise_for_status()
        # print(response.text)

    def stop_node(self, topology_name, node_name):
        """ Power Off VIRl node """

        url = "http://{host}:{port}/simengine/rest/update/{simulation}/stop?nodes={node}".format(host=self.host,
                                                                                                 port=self.std_port,
                                                                                                 simulation=topology_name,
                                                                                                 node=node_name)
        response = requests.request("PUT", url, auth=(self.username, self.password))
        response.raise_for_status()
        # print(response.text)

    def _get_networks(self):
        """ Get information about all available networks on VIRL Server """

        url = "http://{host}:{port}/openstack/rest/networks".format(host=self.host,
                                                                    port=self.std_port)
        response = requests.request("GET", url, auth=(self.username, self.password))
        response.raise_for_status()

        return response

    def get_default_gateway(self, network_name="flat"):
        """ Determine default gateway and network based provided on network name """

        response = self._get_networks()

        def_gateway, subnet = "", ""
        for network in response.json():
            if network["Network Name"] == network_name:
                def_gateway = network["Gateway"]
                subnet = network["CIDR"]
                break
        return def_gateway, subnet

    def get_all_avail_networks(self):
        """ Get list of all available network names """

        response = self._get_networks()

        return [network["Network Name"] for network in response.json()]

    def create_port(self, network_name="flat", port_name="Temporary_Port"):
        """ Power Off VIRl node """

        url = "http://{host}:{port}/openstack/rest/create-port?" \
              "network_name={net_name}&" \
              "port_name={port_name}".format(host=self.host,
                                             port=self.std_port,
                                             net_name=network_name,
                                             port_name=port_name)
        response = requests.request("POST", url, auth=(self.username, self.password))
        response.raise_for_status()

        port_id = response.json().get("port", {}).get("id")
        port_addr = response.json().get("port", {}).get("fixed_ips")[0].get("ip_address")
        if not port_id or not port_addr:
            raise VIRLAPIException("Error happened during port creation determination")

        return port_id, port_addr

    def delete_port(self, port_id):
        """ Power Off VIRl node """

        url = "http://{host}:{port}/rest/vmcontrol/ports/{port_id}".format(host=self.host,
                                                                           port=self.uwm_port,
                                                                           port_id=port_id)
        response = requests.request("DELETE", url, auth=(self.username, self.password))
        response.raise_for_status()
        # print(response.text)

    def get_dhcp_ipaddr(self, network_name="flat", port_name="Temporary_port"):
        """ Get IP address generated by local VIRL DHCP Server
            Used as a hack for NXOS devices because they couldn't get IP address properly
        """

        port_id, port_addr = self.create_port(network_name=network_name, port_name=port_name)
        self.delete_port(port_id=port_id)

        return port_addr

    def get_nodes_info(self, topology_name, network_name="flat"):
        """ Get nodes info """

        nodes_info = {}

        url = "http://{host}:{port}/rest/vmcontrol/nodes".format(host=self.host,
                                                                 port=self.uwm_port)
        response = requests.request("GET", url, auth=(self.username, self.password))
        response.raise_for_status()

        for node in response.json().get("nodes", []):
            match = re.search(r".+-<{topology_name}>-<(?P<node_name>.+)>".format(topology_name=topology_name),
                              node["name"])
            if not match:
                continue

            nodes_info.update({match.group("node_name"): {
                "ip": node.get("addresses", {}).get(network_name, [])[0].get("addr"),
                "mac": node.get("addresses", {}).get(network_name, [])[0].get("OS-EXT-IPS-MAC:mac_addr")
            }})

        return nodes_info

    def get_ifaces_info(self, topology_name):
        """ Get information about all interfaces which are used in provided topology """

        url = "http://{host}:{port}/simengine/rest/interfaces/{topology}".format(host=self.host,
                                                                                 port=self.std_port,
                                                                                 topology=topology_name)
        response = requests.request("GET", url, auth=(self.username, self.password))
        response.raise_for_status()

        ifaces_info = {}
        for node_name, ifaces in response.json().get(topology_name, {}).items():
            ifaces_data = []
            for id, iface_params in ifaces.items():
                try:
                    if id != "management" and int(id) < 0:
                        continue
                except ValueError:  # in case IFace id is not numeric or management
                    pass
                ip_addr = iface_params.get("ip-address") or ""
                ifaces_data.append({"ipv4": ip_addr.split("/")[0],
                                    "ipv6": iface_params.get("ip-address6", ""),
                                    "mac": iface_params.get("hw-addr", ""),
                                    "network": iface_params.get("network", ""),
                                    "port_id": iface_params.get("port_osid", ""),
                                    "mgmt": bool(id == "management")})
            ifaces_info.update({node_name: ifaces_data})

        return ifaces_info

    def get_nodes_status(self, topology_name):
        """  """

        url = "http://{host}:{port}/roster/rest/".format(host=self.host, port=self.std_port)
        response = requests.request("GET", url, auth=(self.username, self.password))
        response.raise_for_status()

        result = {}
        for node_info in response.json().values():
            if not isinstance(node_info, dict):
                continue

            if node_info.get("simID", None) == topology_name:
                result.update({node_info.get("NodeName"): {"console_port": node_info.get("PortConsole", ""),
                                                           "console_server": node_info.get("SimulationHost", ""),
                                                           "is_reachable": node_info.get("Reachable", False),
                                                           "status": node_info.get("Status"),
                                                           "mgmt_ip": node_info.get("managementIP", ""),
                                                           "node_type": node_info.get("NodeSubtype", "")
                                                           }})

        return result

    # def get_available_image_types(self):
    #     """  """
    #
    #     url = "http://{host}:{port}/simengine/rest/subtypes".format(host=self.host, port=self.std_port)
    #     response = requests.request("GET", url, auth=(self.username, self.password))
    #     response.raise_for_status()
    #
    #     return [item["name"] for item in response.json() if item["visible"]]

    def get_available_image_types(self):
        """  """

        url = "http://{host}:{port}/rest/images".format(host=self.host, port=self.uwm_port)
        response = requests.request("GET", url, auth=(self.username, self.password))
        response.raise_for_status()

        return [image.get("properties", {}).get("subtype") for image in response.json().get("images", [])]

    def _change_mgmt_port_state(self, topology_name, node_name, state):
        """ Change Management interface admin_state for provided node
         state = 0 - down
         state = 1 - up
        """

        url = "http://{host}:{port}/simengine/rest/update/interfaces/{topology_name}" \
              "?nodes={node_name}" \
              "&interfaces=management" \
              "&link-state={link_state}".format(host=self.host,
                                                port=self.std_port,
                                                topology_name=topology_name,
                                                node_name=node_name,
                                                link_state=state)
        response = requests.request("PUT", url, auth=(self.username, self.password))
        response.raise_for_status()
        print(response.json())

    def reboot_mgmt_port(self, topology_name, node_name):
        """ Reboot Management interface port """

        try:
            self._change_mgmt_port_state(topology_name=topology_name, node_name=node_name, state=0)  # Shutdown port
            time.sleep(IFACE_REBOOT_TIMEOUT)
            self._change_mgmt_port_state(topology_name=topology_name, node_name=node_name, state=1)  # Startup port
        except:
            pass


if __name__ == "__main__":
    virl_api = VIRL_API(host="192.168.26.111")

    virl_api.reboot_mgmt_port(topology_name="2778394d-8f23-4f58-8152-bcefc64cfd7b", node_name="NXOSv")

    # virl_api.create_port()
    # print(virl_api.get_default_gateway())
    # try:
    #     print(virl_api.get_all_avail_networks())
    # except requests.HTTPError as err:
    #     print(err)
    # print(virl_api.get_nodes_info(topology_name="topology-gGHRLy-RLVF0P-7wsn_P"))
    # for node, data in virl_api.get_ifaces_info(topology_name="topology-gGHRLy-RLVF0P-7wsn_P").items():
    # topology_data = open("../_develop/data/simple.virl", 'rb').read()
    # virl_api.upload_topology(topology_data=topology_data, reservation_id="QUALI_RES_ID")
    # for node, data in virl_api.get_ifaces_info(topology_name="QUALI_RES_ID").items():
    #     print(node)
    #     for iface in data:
    #         for k, v in iface.items():
    #             print(f"\t {k} {v}")
    #         print()

    # print(virl_api.get_available_image_types())

    # for name, data in virl_api.get_node_status(topology_name="topology-gGHRLy-RLVF0P-7wsn_P").items():
    # for name, data in virl_api.get_nodes_status(topology_name="ac4abbff-742a-470f-a970-ac5d93639025").items():
    #     print(name)
    #     for k, v in data.items():
    #         print(k, v)
    #     print()

    # topology_data = open("../_develop/data/virl_topology.virl", 'rb').read()
    # virl_api.upload_topology(reservation_id="Quali_Res_ID", topology_data=topology_data)
    # virl_api.start_node(topology_name="Quali_Res_ID", node_name="Router 1")
    # virl_api.stop_node(topology_name="Quali_Res_ID", node_name="Router 1")
    # virl_api.stop_topology(topology_name="Quali_Res_ID")

{'IOS XRv 9000': [{'ipv4': '', 'ipv6': None, 'mac': 'fa:16:3e:1f:5e:0f', 'network': 'IOS XRv 9000-Dummy/DevEth',
                   'port_id': '0f6720a9-919c-450c-a229-a55b530d594d', 'mgmt': False},
                  {'ipv4': '', 'ipv6': None, 'mac': 'fa:16:3e:60:27:1b', 'network': 'IOS XRv 9000-Dummy/CtrlEth',
                   'port_id': '5898f97b-ce15-468b-878f-c0234761be63', 'mgmt': False},
                  {'ipv4': '192.168.105.97', 'ipv6': None, 'mac': '5e:00:80:00:00:00', 'network': 'flat',
                   'port_id': '7e5744eb-915d-465d-be51-b89d2ec469f7', 'mgmt': True}]}
{'IOS XRv 9000': {'console_port': 17001, 'console_server': '192.168.26.111', 'is_reachable': True, 'status': 'ACTIVE',
                  'mgmt_ip': '192.168.105.97', 'node_type': 'IOS XRv 9000'}}
