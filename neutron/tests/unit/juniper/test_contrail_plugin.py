# Copyright (c) 2012 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import copy
import datetime
import sys
import uuid

import json
import netaddr
import mock
from oslo.config import cfg
import webob.exc

from neutron.api import extensions
import neutron.db.api
from neutron.manager import NeutronManager
from neutron.tests.unit import test_db_plugin as test_plugin
from neutron.tests.unit import test_extensions
from neutron.tests.unit import test_extension_security_group as test_sg
from neutron.tests.unit import testlib_api

VN_LIST = []


class keystone_info_class(object):
    """To generate Keystone Authentication information

    Contrail Driver expects Keystone auth info for testing purpose.
    """
    auth_protocol = 'http'
    auth_host = 'host'
    auth_port = 5000
    admin_user = 'neutron'
    admin_password = 'neutron'
    admin_token = 'neutron'
    admin_tenant_name = 'neutron'


class MockRequestsResponse(mock.MagicMock):
    def __init__(self, code=None, resp_data=None,
                 *args, **kwargs):
        super(MockRequestsResponse, self).__init__()
        self.status_code = code
        self.content = resp_data

    def set_status_code(self, resp_data):
        status_code = resp_data

    def set_content(self, data):
        content = data


def fake_get_network(net_id):
    for vn in VN_LIST:
        if vn['id'] == net_id:
            net = {'q_api_data': vn, 'q_extra_data': {}}
            return MockRequestsResponse(200, json.dumps(net))

    return MockRequestsResponse(200, '')


def fake_create_network(network):
    net_id = unicode(str(uuid.uuid4()))
    network['id'] = net_id
    network['status'] = 'ACTIVE'
    network['subnets'] = []
    VN_LIST.append(network)
    net = {'q_api_data': network, 'q_extra_data': {}}
    return MockRequestsResponse(200, json.dumps(net))


def fake_update_network(net_id, network):
    for vn in VN_LIST:
        if vn['id'] == net_id:
            for key in network:
                vn[key] = network[key]

            net = {'q_api_data': vn, 'q_extra_data': {}}
            return MockRequestsResponse(200, json.dumps(net))


def fake_delete_network(net_id):
    for vn in VN_LIST:
        if vn['id'] == net_id:
            VN_LIST.remove(vn)


def fake_get_networks_all(filters):
    nets = []
    for vn in VN_LIST:
        include = 'yes'
        if filters:
            for key in filters:
                for val in filters[key]:
                    if vn[key] != val:
                        include = None

        if include:
            net = {'q_api_data': vn, 'q_extra_data': {}}
            nets.append(net)
    return MockRequestsResponse(200, json.dumps(nets))


def fake_get_network_count():
    retval = json.dumps({'count': len(VN_LIST)})
    return MockRequestsResponse(200, retval)


def fake_handle_network_requests(context, data):
    operation = context['operation']

    if operation == 'READ':
        return fake_get_network(net_id=data['net_id'])
    elif operation == 'CREATE':
        return fake_create_network(data['network'])
    elif operation == 'UPDATE':
        return fake_update_network(data['net_id'], data['network'])
    elif operation == 'DELETE':
        return fake_delete_network(net_id=data['net_id'])
    elif operation == 'READALL':
        return fake_get_networks_all(data['filters'])
    elif operation == 'READCOUNT':
        return fake_get_network_count()


class FakeResources(object):
    _store = {}

    def __init__(self, res_type, addr_mgmt=None):
        self._type = res_type
        self._store[res_type] = {}
        self._addr_mgmt = addr_mgmt
        self._tenants = []

    def _filters_is_present(self, filters, key_name, match_value):
        if filters:
            if key_name in filters:
                try:
                    filters[key_name].index(match_value)
                except ValueError:
                    return False

        return True

    def _check_tenant(self, tenant_id):
        if tenant_id in self._tenants:
            return
        self._tenants.append(tenant_id)
        fake_resources['security_group']._create_default_security_group(
            tenant_id)

    def reset(self):
        self._store[self._type] = {}
        self._addr_mgmt = None

    def do_operation(self, context, data):
        operation = context['operation']

        if operation == 'READ':
            return self.read(id=data['id'])
        elif operation == 'CREATE':
            return self.create(data['resource'])
        elif operation == 'UPDATE':
            return self.update(data['id'], data['resource'])
        elif operation == 'DELETE':
            return self.delete(data['id'], context=context)
        elif operation == 'READALL':
            return self.list(data['filters'], context=context)
        elif operation == 'READCOUNT':
            return self.count(data['filters'])

    def create(self, res_data):
        res_id = res_data.get('id', str(uuid.uuid4()))
        res_data['id'] = res_id
        res_data['status'] = 'ACTIVE'
        self._store[self._type][res_id] = copy.deepcopy(res_data)
        mock_response = MockRequestsResponse(200, json.dumps(res_data))
        return mock_response

    def read(self, id):
        res_data = self._store[self._type][id]
        return MockRequestsResponse(200, json.dumps(res_data))

    def update(self, id, res_data):
        self._store[self._type][id].update(copy.deepcopy(res_data))
        ret_data = self._store[self._type][id]
        return MockRequestsResponse(200, json.dumps(ret_data))

    def delete(self, id, context=None):
        del self._store[self._type][id]
        return MockRequestsResponse(200, json.dumps(''))

    def _filter_check(self, filters, resource):
        for filter in filters or []:
            if not self._filters_is_present(filters, filter,
                                            resource.get(filter)):
                return False
        return True

    def list(self, filters, context=None):
        resources = self._store[self._type]
        ret_resources = []
        for res_id in resources:
            resource = resources[res_id]
            if not self._filter_check(filters, resource):
                continue

            if self._type == 'security_group':
                resource['rules'] = []
                for rule in self._store['security_group_rule'].values():
                    if rule['security_group_id'] == resource['id']:
                        resource['rules'].append(rule)
            ret_resources.append(copy.deepcopy(resource))

        return MockRequestsResponse(200, json.dumps(ret_resources))

    def count(self, filters):
        ret_resources = self._store[self._type]
        retval = json.dumps({'count': len(ret_resources)})
        return MockRequestsResponse(200, retval)


class FakeNetworks(FakeResources):
    def __init__(self, addr_mgmt):
        super(FakeNetworks, self).__init__('network', addr_mgmt)

    def _ports_on_network(self, network_id, network_owned=False):
        ret_ports = []
        for port_id in self._store['port']:
            port = self._store['port'][port_id]
            if port['network_id'] == network_id:
                if (network_owned and port['device_owner'] == 'network:dhcp'):
                    ret_ports.append(port)
                elif (not network_owned and
                      port['device_owner'] != 'network:dhcp'):
                    ret_ports.append(port)

        return ret_ports

    def create(self, req_network_data):
        network_data = copy.deepcopy(req_network_data)
        self._check_tenant(network_data['tenant_id'])
        network_data['subnets'] = []
        response = super(FakeNetworks, self).create(network_data)

        return response

    def update(self, id, req_network_data):
        existing_network = self._store['network'][id]
        if (req_network_data.get('shared') is False and
                existing_network['shared'] is True):
            ports_on_network = self._ports_on_network(id, False)
            network_tenant_id = existing_network['tenant_id']
            for port in ports_on_network:
                if port['tenant_id'] != network_tenant_id:
                    exc_info = {'type': 'InvalidSharedSetting',
                                'name': existing_network['name']}
                    return MockRequestsResponse(409, json.dumps(exc_info))

        response = super(FakeNetworks, self).update(id, req_network_data)
        if req_network_data.get('shared') is not None:
            for subnet_data in existing_network['subnets']:
                subnet_dict = self._store['subnet'][subnet_data['id']]
                subnet_dict['shared'] = req_network_data['shared']

        return response

    def delete(self, id, context=None):
        non_network_owned_ports = self._ports_on_network(id, False)
        if non_network_owned_ports:
            exc_info = {'type': 'NetworkInUse',
                        'network_id': id}
            return MockRequestsResponse(409, json.dumps(exc_info))

        network_owned_ports = self._ports_on_network(id, True)
        for port in network_owned_ports:
            del self._store['port'][port['id']]

        return super(FakeNetworks, self).delete(id, context)

    def list(self, filters, context=None):
        return super(FakeNetworks, self).list(filters)


class FakeSubnets(FakeResources):
    def __init__(self, addr_mgmt):
        super(FakeSubnets, self).__init__('subnet', addr_mgmt)

    def _generate_gw_alloc_pools(self, cidr, gw):
        alloc_pools = []
        gateway_ip = None
        if not gw or gw == '0.0.0.0':
            if not gw:
                gateway_ip = str(netaddr.IPNetwork(cidr).network + 1)
            start_ip = str(netaddr.IPNetwork(cidr).network + 2)
            end_ip = str(netaddr.IPNetwork(cidr).broadcast - 1)
            alloc_pool = {'first_ip': start_ip,
                          'last_ip': end_ip}
            alloc_pools.append(alloc_pool)
        else:
            gateway_ip = gw
            if netaddr.IPAddress(gw) not in netaddr.IPNetwork(cidr):
                start_ip = str(netaddr.IPNetwork(cidr).network + 1)
                end_ip = str(netaddr.IPNetwork(cidr).broadcast - 1)
                alloc_pool = {'first_ip': start_ip,
                              'last_ip': end_ip}
                alloc_pools.append(alloc_pool)
            else:  # gateway in cidr
                # no prefix pool if gw is first in cidr
                if gw != str(netaddr.IPNetwork(cidr).network + 1):
                    start_ip = str(netaddr.IPNetwork(cidr).network + 1)
                    end_ip = str(netaddr.IPAddress(gw) - 1)
                    alloc_pool = {'first_ip': start_ip,
                                  'last_ip': end_ip}
                    alloc_pools.append(alloc_pool)

                # no suffix pool if gw is last in cidr
                if gw != str(netaddr.IPNetwork(cidr).broadcast - 1):
                    start_ip = str(netaddr.IPAddress(gw) + 1)
                    end_ip = str(netaddr.IPNetwork(cidr).broadcast - 1)
                    alloc_pool = {'first_ip': start_ip,
                                  'last_ip': end_ip}
                    alloc_pools.append(alloc_pool)

        return gateway_ip, alloc_pools

    def _validate_gw_alloc_pools(self, cidr, gw, alloc_pools):
        if gw:
            if gw == '0.0.0.0':
                return True, None
            else:
                return True, gw

        gateway_ip = str(netaddr.IPNetwork(cidr).network + 1)
        for pool in alloc_pools:
            if gateway_ip in netaddr.IPRange(pool['start'],
                                             pool['end']):
                exc_info = {'type': 'GatewayConflictWithAllocationPools',
                            'pool': pool,
                            'ip_address': gateway_ip}
                return False, MockRequestsResponse(409, json.dumps(exc_info))

        return True, gateway_ip

    def _set_host_routes(self, req_host_routes, subnet_data):
        subnet_data['routes'] = []
        for host_route in req_host_routes or []:
            route = {'destination': host_route['destination'],
                     'nexthop': host_route['nexthop']}
            subnet_data['routes'].append(route)

    def _ports_on_subnet(self, subnet_id, network_owned=False):
        ret_ports = []
        for port_id in self._store['port']:
            port = self._store['port'][port_id]
            for fixed_ip_dict in port.get('fixed_ips') or []:
                if fixed_ip_dict['subnet_id'] == subnet_id:
                    if (network_owned and
                            port['device_owner'] == 'network:dhcp'):
                        ret_ports.append(port)
                    elif (not network_owned and
                          port['device_owner'] != 'network:dhcp'):
                        ret_ports.append(port)

        return ret_ports

    def _ports_on_subnet_with_gateway_ip(self, subnet_id):
        ret_ports = []
        existing_subnet = self._store['subnet'][subnet_id]

        non_network_owned_ports = self._ports_on_subnet(subnet_id, False)
        for port in non_network_owned_ports:
            for fixed_ip_dict in port['fixed_ips']:
                address = fixed_ip_dict['ip_address']
                if existing_subnet['gateway_ip'] == address:
                    ret_ports.append(port)

        return ret_ports

    def create(self, req_subnet_data):
        subnet_data = copy.deepcopy(req_subnet_data)

        subnet_data['dns_nameservers'] = []
        subnet_id = subnet_data.get('id', str(uuid.uuid4()))
        subnet_data['id'] = subnet_id
        network_id = subnet_data['network_id']
        for dns_server in req_subnet_data['dns_nameservers'] or []:
            dns = {'address': dns_server,
                   'subnet_id': subnet_id}
            subnet_data['dns_nameservers'].append(dns)

        self._set_host_routes(req_subnet_data['host_routes'], subnet_data)

        subnet_data['shared'] = self._store['network'][network_id]['shared']

        cidr = req_subnet_data['cidr']
        gw = req_subnet_data.get('gateway_ip', None)
        if not req_subnet_data['allocation_pools']:
            gw, alloc_pools = self._generate_gw_alloc_pools(cidr, gw)
            subnet_data['allocation_pools'] = alloc_pools
            subnet_data['gateway_ip'] = gw
        else:
            alloc_pools = subnet_data['allocation_pools']
            ok, retval = self._validate_gw_alloc_pools(cidr, gw, alloc_pools)
            if not ok:
                response = retval
                return response

            gw = retval
            subnet_data['gateway_ip'] = gw
            for pool in alloc_pools:
                pool['first_ip'] = pool['start']
                pool['last_ip'] = pool['end']
                del pool['start']
                del pool['end']

        response = super(FakeSubnets, self).create(subnet_data)
        self._addr_mgmt.create_subnet(subnet_data)

        self._store['network'][network_id]['subnets'].append(subnet_data)

        return response

    def read(self, id):
        try:
            return super(FakeSubnets, self).read(id)
        except KeyError:
            exc_info = {'type': 'SubnetNotFound',
                        'id': id}
            return MockRequestsResponse(404, json.dumps(exc_info))

    def update(self, id, req_subnet_data):
        subnet_data = copy.deepcopy(req_subnet_data)

        if ('gateway_ip' in subnet_data and
                self._ports_on_subnet_with_gateway_ip(id)):
            exc_info = {'type': 'SubnetInUse',
                        'id': id}
            return MockRequestsResponse(409, json.dumps(exc_info))

        if 'host_routes' in req_subnet_data:
            self._set_host_routes(req_subnet_data['host_routes'], subnet_data)

        if 'dns_nameservers' in req_subnet_data:
            new_dns_nameservers = req_subnet_data['dns_nameservers']
            subnet_data['dns_nameservers'] = []
            for dns_server in new_dns_nameservers or []:
                dns = {'address': dns_server,
                       'subnet_id': id}
                subnet_data['dns_nameservers'].append(dns)

        response = super(FakeSubnets, self).update(id, subnet_data)
        self._addr_mgmt.update_subnet(subnet_data)

        return response

    def delete(self, id, context):
        non_network_owned_ports = self._ports_on_subnet(id, False)
        if self._ports_on_subnet(id):
            exc_info = {'type': 'SubnetInUse',
                        'id': id}
            return MockRequestsResponse(409, json.dumps(exc_info))

        network_owned_ports = self._ports_on_subnet(id, True)
        for port in network_owned_ports:
            del self._store['port'][port['id']]

        network_id = self._store['subnet'][id]['network_id']
        rem_subnets = \
            [sn for sn in self._store['network'][network_id][
                'subnets'] if sn['id'] != id]
        self._store['network'][network_id]['subnets'] = rem_subnets
        self._addr_mgmt.delete_subnet(id)
        response = super(FakeSubnets, self).delete(id, context)

        return response


class FakePorts(FakeResources):
    def __init__(self, addr_mgmt):
        super(FakePorts, self).__init__('port', addr_mgmt)

    def _ip_to_subnet_id(self, network_id, fixed_ip_dict):
        if fixed_ip_dict.get('subnet_id'):
            return (fixed_ip_dict['subnet_id'],
                    fixed_ip_dict.get('ip_address'))

        for subnet in self._store['network'][network_id]['subnets']:
            if fixed_ip_dict['ip_address'] in netaddr.IPNetwork(
                    subnet['cidr']):
                return (subnet['id'], fixed_ip_dict['ip_address'])

        return None, fixed_ip_dict['ip_address']

    def create(self, req_port_data):
        port_data = copy.deepcopy(req_port_data)
        self._check_tenant(port_data['tenant_id'])
        if not port_data.get('id'):
            port_data['id'] = str(uuid.uuid4())

        req_fixed_ips = port_data['fixed_ips']
        if req_fixed_ips:
            network_id = port_data['network_id']
            for fixed_ip_dict in req_fixed_ips:
                fixed_ip_dict['subnet_id'] = \
                    self._ip_to_subnet_id(network_id, fixed_ip_dict)[0]
                if not self._addr_mgmt.is_ip_unique(fixed_ip_dict['subnet_id'],
                                                    fixed_ip_dict.get(
                                                        'ip_address')):
                    exc_info = {'type': 'IpAddressInUse',
                                'network_id': port_data['network_id'],
                                'ip_address': fixed_ip_dict['ip_address']}
                    return MockRequestsResponse(409, json.dumps(exc_info))
            for fixed_ip_dict in req_fixed_ips:
                subnet_id = fixed_ip_dict['subnet_id']
                address = fixed_ip_dict.get('ip_address')
                if not address:
                    subnet_id, address = self._addr_mgmt.alloc_ip_subnet(
                        subnet_id, port_data['id'])
                    fixed_ip_dict['ip_address'] = address
                self._addr_mgmt.create_ip(subnet_id, address, port_data['id'])
        else:
            port_data['fixed_ips'] = []
            network_id = port_data['network_id']
            subnets = self._store['network'][network_id]['subnets']
            if subnets:
                subnet_id, address = self._addr_mgmt.alloc_ip(network_id,
                                                              port_data['id'],
                                                              4)
                if address:
                    self._addr_mgmt.create_ip(subnet_id, address,
                                              port_data['id'])
                    port_data['fixed_ips'].append({'subnet_id': subnet_id,
                                                   'ip_address': address})
                else:
                    exc_info = {'type': 'IpAddressGenerationFailure',
                                'network_id': network_id}
                    return MockRequestsResponse(409, json.dumps(exc_info))

                subnet_id, address = self._addr_mgmt.alloc_ip(network_id,
                                                              port_data['id'],
                                                              6)
                if address:
                    self._addr_mgmt.create_ip(subnet_id, address,
                                              port_data['id'])
                    port_data['fixed_ips'].append({'subnet_id': subnet_id,
                                                   'ip_address': address})

        if 'security_groups' not in port_data:
            for sg in self._store['security_group'].values():
                if sg['tenant_id'] == port_data['tenant_id'] and sg[
                        'name'] == 'default':
                    port_data['security_groups'] = [sg['id']]
                    break

        response = super(FakePorts, self).create(port_data)
        return response

    def update(self, id, req_port_data):
        port_data = copy.deepcopy(req_port_data)
        existing_port = self._store['port'][id]

        req_fixed_ips = port_data.get('fixed_ips')
        if req_fixed_ips:
            network_id = existing_port['network_id']
            existing_fixed_ips = existing_port['fixed_ips']
            existing_port['fixed_ips'] = []
            for req_fixed_ip in req_fixed_ips:
                subnet_id, ip = self._ip_to_subnet_id(network_id, req_fixed_ip)
                for port_ip in existing_fixed_ips:
                    if subnet_id == port_ip['subnet_id'] and ip in [
                            None, port_ip['ip_address']]:
                        existing_port['fixed_ips'].append(port_ip)
                        existing_fixed_ips.remove(port_ip)
                        break
                else:
                    if ip:
                        self._addr_mgmt.create_ip(subnet_id, ip,
                                                  existing_port['id'])
                        existing_port['fixed_ips'].append(
                            {'subnet_id': subnet_id, 'ip_address': ip})
                    else:
                        subnet_id, address = \
                            self._addr_mgmt.alloc_ip_subnet(
                                subnet_id, existing_port['id'])
                        if address:
                            self._addr_mgmt.create_ip(subnet_id, address,
                                                      existing_port['id'])
                            existing_port['fixed_ips'].append(
                                {'subnet_id': subnet_id,
                                 'ip_address': address})
                        else:
                            exc_info = {'type': 'IpAddressGenerationFailure',
                                        'network_id': network_id}
                            return MockRequestsResponse(409,
                                                        json.dumps(exc_info))

            for fixed_ip in existing_fixed_ips:
                self._addr_mgmt.delete_ip(fixed_ip['subnet_id'],
                                          fixed_ip['ip_address'],
                                          existing_port['id'])
            port_data['fixed_ips'] = existing_port['fixed_ips']

        response = super(FakePorts, self).update(id, port_data)
        return response

    def delete(self, id, context):
        existing_port = self._store['port'][id]
        response = super(FakePorts, self).delete(id, context)

        for fixed_ips in existing_port['fixed_ips']:
            self._addr_mgmt.delete_ip(fixed_ips['subnet_id'],
                                      fixed_ips['ip_address'], id)

        return response

    def list(self, filters, context=None):
        if 'fixed_ips' in filters:
            ret_ports = []
            ports = [self._store['port'][id] for id in self._store['port']]
            for port in ports:
                for fixed_ip in port.get('fixed_ips', []):
                    if (fixed_ip['subnet_id'] in filters['fixed_ips'][
                            'subnet_id'] and
                        fixed_ip['ip_address'] in filters['fixed_ips'][
                            'ip_address']):
                        ret_ports.append(port)
            return MockRequestsResponse(200, json.dumps(ret_ports))

        return super(FakePorts, self).list(filters)


class FakeSecurityGroups(FakeResources):
    def __init__(self):
        super(FakeSecurityGroups, self).__init__('security_group')

    def _update_rules(self, resource):
        sg_id = resource['id']
        resource['rules'] = []
        for rule in self._store['security_group_rule'].values():
            if rule['security_group_id'] == resource['id']:
                resource['rules'].append(copy.deepcopy(rule))

    def create(self, req_sg_data):
        sg_data = copy.deepcopy(req_sg_data)
        sg_id = sg_data.get('id', str(uuid.uuid4()))
        sg_data['id'] = sg_id
        tenant_id = sg_data['tenant_id']
        response = super(FakeSecurityGroups, self).create(sg_data)
        rule1 = {'remote_group_id': None, 'direction': 'egress',
                 'protocol': None, 'ethertype': 'IPv4',
                 'port_range_max': None, 'security_group_id': sg_id,
                 'tenant_id': tenant_id, 'port_range_min': None,
                 'remote_ip_prefix': None}
        rule2 = {'remote_group_id': None, 'direction': 'egress',
                 'protocol': None, 'ethertype': 'IPv6',
                 'port_range_max': None, 'security_group_id': sg_id,
                 'tenant_id': tenant_id, 'port_range_min': None,
                 'remote_ip_prefix': None}
        fake_resources['security_group_rule'].create(rule1)
        fake_resources['security_group_rule'].create(rule2)
        self._update_rules(sg_data)
        return MockRequestsResponse(200, json.dumps(sg_data))

    def read(self, id):
        res_data = self._store[self._type][id]
        resource = copy.deepcopy(res_data)
        self._update_rules(resource)
        return MockRequestsResponse(200, json.dumps(resource))

    def _find_security_group(self, tenant_id, sg_name):
        for sg in self._store['security_group'].values():
            if sg['tenant_id'] == tenant_id and sg['name'] == sg_name:
                return sg
        return None

    def _create_default_security_group(self, tenant_id):
        if not self._find_security_group(tenant_id, "default"):
            sg_id = str(uuid.uuid4())
            self.create({'id': sg_id, 'tenant_id': tenant_id,
                         'name': 'default'})
            rule1 = {'remote_group_id': sg_id, 'direction': 'ingress',
                     'protocol': None, 'ethertype': 'IPv4',
                     'port_range_max': None, 'security_group_id': sg_id,
                     'tenant_id': tenant_id, 'port_range_min': None,
                     'remote_ip_prefix': None}
            rule2 = {'remote_group_id': sg_id, 'direction': 'ingress',
                     'protocol': None, 'ethertype': 'IPv6',
                     'port_range_max': None, 'security_group_id': sg_id,
                     'tenant_id': tenant_id, 'port_range_min': None,
                     'remote_ip_prefix': None}

            fake_resources['security_group_rule'].create(rule1)
            fake_resources['security_group_rule'].create(rule2)

    def list(self, filters, context=None):
        tenant_id = filters.get('tenant_id') or context.get('tenant_id')
        if tenant_id:
            self._create_default_security_group(tenant_id)
        return super(FakeSecurityGroups, self).list(filters)

    def delete(self, id, context):
        sg = self._store['security_group'][id]
        if sg['name'] == 'default' and 'admin' not in context.get('roles', []):
            exc_info = {'type': 'SecurityGroupCannotRemoveDefault'}
            return MockRequestsResponse(409, json.dumps(exc_info))

        for port in self._store['port'].values():
            if id in port.get('security_groups', []):
                exc_info = {'type': 'SecurityGroupInUse'}
                return MockRequestsResponse(409, json.dumps(exc_info))

        return super(FakeSecurityGroups, self).delete(id, context)


class FakeSecurityGroupRules(FakeResources):
    def __init__(self):
        super(FakeSecurityGroupRules, self).__init__('security_group_rule')

    def create(self, req_data):
        data = copy.deepcopy(req_data)
        tenant_id = data['tenant_id']
        sg_id = data['security_group_id']

        if data.get('remote_group_id') and data.get('remote_ip_prefix'):
            exc_info = {
                'type': 'BadRequest',
                'msg': "Can't specify both remote security group and prefix"}
            return MockRequestsResponse(409, json.dumps(exc_info))
        if data.get('port_range_min') and data.get('protocol') is None:
            exc_info = {
                'type': 'BadRequest',
                'msg': "Protocol must be specified if port range is specified"}
            return MockRequestsResponse(409, json.dumps(exc_info))
        if data.get('protocol') != 'icmp':
            if ((data.get('port_range_min') and data.get(
                    'port_range_max') is None) or
                (data.get('port_range_max') and data.get(
                    'port_range_min') is None)):
                exc_info = {
                    'type': 'BadRequest',
                    'msg': "Port range min and max must be specified together"}
                return MockRequestsResponse(409, json.dumps(exc_info))
            if (data.get('port_range_min') > data.get('port_range_max')):
                exc_info = {
                    'type': 'BadRequest',
                    'msg': "Port range min must not be greater than max"}
                return MockRequestsResponse(409, json.dumps(exc_info))
        if data.get('protocol') == 'icmp':
            if data.get('port_range_max') > 255:
                exc_info = {'type': 'BadRequest',
                            'msg': "ICMP code must be less than 256"}
                return MockRequestsResponse(409, json.dumps(exc_info))
            if data.get('port_range_min') > 255:
                exc_info = {'type': 'BadRequest',
                            'msg': "ICMP type must be less than 256"}
                return MockRequestsResponse(409, json.dumps(exc_info))

        for rule in self._store['security_group_rule'].values():
            if (rule.get('security_group_id') == data.get(
                'security_group_id') and
                rule.get('direction') == data.get('direction') and
                rule.get('ethertype') == data.get('ethertype') and
                rule.get('protocol') == data.get('protocol') and
                rule.get('port_range_min') == data.get('port_range_min') and
                rule.get('port_range_max') == data.get('port_range_max') and
                rule.get('remote_group_id') == data.get('remote_group_id') and
                    rule.get('remote_ip_prefix') == data.get(
                        'remote_ip_prefix')):
                exc_info = {'type': 'Conflict',
                            'msg': "Duplicate rules cannot be specified"}
                return MockRequestsResponse(409, json.dumps(exc_info))

        sg = self._store['security_group'].get(sg_id)
        if sg is None:
            exc_info = {'type': 'NotFound',
                        'msg': "Security group id not found"}
            return MockRequestsResponse(409, json.dumps(exc_info))
        if tenant_id != sg['tenant_id']:
            exc_info = {'type': 'NotFound',
                        'msg': "Tenant id not found"}
            return MockRequestsResponse(409, json.dumps(exc_info))
        remote_sg_id = data.get('remote_group_id')
        remote_sg = self._store['security_group'].get(
            remote_sg_id) if remote_sg_id else None

        if remote_sg and tenant_id != remote_sg['tenant_id']:
            exc_info = {'type': 'NotFound',
                        'msg': "Tenant id not found"}
            return MockRequestsResponse(409, json.dumps(exc_info))
        response = super(FakeSecurityGroupRules, self).create(data)
        return response


class FakeAddrMgmt(object):
    def __init__(self):
        self._subnet_dicts = {}
        self._ip_dicts = {}

    def create_subnet(self, subnet_data):
        network_id = subnet_data['network_id']
        subnet_id = subnet_data['id']
        if subnet_id not in self._subnet_dicts:
            self._subnet_dicts[subnet_id] = {}

        alloc_pools = subnet_data['allocation_pools']
        subnet_dict = self._subnet_dicts[subnet_id]
        subnet_dict.update({'network_id': network_id,
                            'id': subnet_id,
                            'alloc_pools': alloc_pools,
                            'used_addrs': [],
                            'ip_to_port': {},
                            'ip_version': subnet_data.get('ip_version')})

    def update_subnet(self, subnet_data):
        pass

    def delete_subnet(self, id):
        pass

    def _get_free_ip(self, pool, used_addrs):
        for ip in netaddr.iter_iprange(pool['first_ip'], pool['last_ip']):
            if str(ip) not in used_addrs:
                return str(ip)

        return None

    def is_ip_unique(self, subnet_id, ip_address):
        subnet_dict = self._subnet_dicts[subnet_id]
        if ip_address in subnet_dict['ip_to_port']:
            return False

        return True

    def alloc_ip_subnet(self, subnet_id, port_id):
        subnet_dict = self._subnet_dicts[subnet_id]
        for pool in subnet_dict['alloc_pools']:
            address = self._get_free_ip(pool, subnet_dict['used_addrs'])
            if address:
                return subnet_dict['id'], address

    def alloc_ip(self, network_id, port_id, ip_version):
        subnet_dicts = [sn for sn in self._subnet_dicts.values(
            ) if sn['network_id'] == network_id and sn[
            'ip_version'] == ip_version]

        for subnet_dict in subnet_dicts:
            for pool in subnet_dict['alloc_pools']:
                address = self._get_free_ip(pool, subnet_dict['used_addrs'])
                if address:
                    return subnet_dict['id'], address

        return None, None

    def create_ip(self, subnet_id, address, port_id):
        subnet_dict = self._subnet_dicts[subnet_id]
        subnet_dict['used_addrs'].append(address)
        subnet_dict['ip_to_port'][address] = port_id

    def delete_ip(self, subnet_id, address, port_id):
        subnet_dict = self._subnet_dicts[subnet_id]
        subnet_dict['used_addrs'].remove(address)
        del subnet_dict['ip_to_port'][address]

fake_resources = {}
addr_mgmt = None


def initialize_fakes():
    global fake_resources, addr_mgmt

    addr_mgmt = FakeAddrMgmt()
    fake_resources = {
        'network': FakeNetworks(addr_mgmt),
        'subnet': FakeSubnets(addr_mgmt),
        'port': FakePorts(addr_mgmt),
        'security_group': FakeSecurityGroups(),
        'security_group_rule': FakeSecurityGroupRules(),
        }


def reset_fakes():
    global fake_resources
    for type in fake_resources:
        fake_resources[type].reset()


def fake_requests_post(*args, **kwargs):
    postdata = json.loads(kwargs['data'])
    context = postdata['context']
    data = postdata['data']

    return fake_resources[context['type']].do_operation(context, data)

fake_requests = mock.MagicMock(name='fake_requests_pkg')
sys.modules['requests'] = fake_requests
fake_requests.post = fake_requests_post

CONTRAIL_PKG_PATH = "neutron.plugins.opencontrail.contrail_plugin_core"


class RouterInstance(object):
    def __init__(self):
        self._name = 'rounter_instance'


class Context(object):
    def __init__(self, tenant_id=''):
        self.read_only = False
        self.show_deleted = False
        self.roles = [u'admin', u'KeystoneServiceAdmin', u'KeystoneAdmin']
        self._read_deleted = 'no'
        self.timestamp = datetime.datetime.now()
        self.auth_token = None
        self._session = None
        self._is_admin = True
        self.admin = uuid.uuid4().hex.decode()
        self.request_id = 'req-' + str(uuid.uuid4())
        self.tenant = tenant_id


class JVContrailPluginTestCase(test_plugin.NeutronDbPluginV2TestCase):
    _plugin_name = ('%s.NeutronPluginContrailCoreV2' % CONTRAIL_PKG_PATH)

    def setUp(self, plugin=None, ext_mgr=None):

        cfg.CONF.keystone_authtoken = keystone_info_class()
        super(JVContrailPluginTestCase, self).setUp(self._plugin_name)
        cfg.CONF.set_override('quota_driver', 'neutron.quota.ConfDriver',
                              group='QUOTAS')

    def teardown(self):
        super(JVContrailPluginTestCase, self).setUp(self._plugin_name)


class TestContrailNetworks(test_plugin.TestNetworksV2,
                           JVContrailPluginTestCase):
    def setUp(self):
        initialize_fakes()
        super(TestContrailNetworks, self).setUp()

    def tearDown(self):
        super(TestContrailNetworks, self).tearDown()
        reset_fakes()


class TestContrailSubnetsV2(test_plugin.TestSubnetsV2,
                            JVContrailPluginTestCase):
    def setUp(self):
        initialize_fakes()
        super(TestContrailSubnetsV2, self).setUp()

    def tearDown(self):
        super(TestContrailSubnetsV2, self).tearDown()
        reset_fakes()

    def test_create_subnets_bulk_emulated_plugin_failure(self):
        pass

    def test_create_subnet_bad_tenant(self):
        pass

    def test_update_subnet_ipv6_attributes(self):
        pass

    def test_update_subnet_ipv6_inconsistent_address_attribute(self):
        pass

    def test_update_subnet_ipv6_inconsistent_enable_dhcp(self):
        pass

    def test_update_subnet_ipv6_inconsistent_ra_attribute(self):
        pass

    def test_delete_subnet_dhcp_port_associated_with_other_subnets(self):
        pass

    def test_create_subnet_nonzero_cidr(self):
        pass


class TestContrailPortsV2(test_plugin.TestPortsV2,
                          JVContrailPluginTestCase):
    def setUp(self):
        initialize_fakes()
        super(TestContrailPortsV2, self).setUp()

    def tearDown(self):
        super(TestContrailPortsV2, self).tearDown()
        reset_fakes()

    def test_mac_exhaustion(self):
        pass

    def test_create_port_bad_tenant(self):
        pass

    def test_mac_generation_4octet(self):
        pass

    def test_mac_generation(self):
        pass

    def test_update_fixed_ip_lease_expiration_invalid_address(self):
        pass

    def test_requested_duplicate_mac(self):
        pass

    def test_recycle_ip_address_in_allocation_pool(self):
        pass

    def test_recycle_ip_address_outside_allocation_pool(self):
        pass

    def test_recycle_ip_address_on_exhausted_allocation_pool(self):
        pass

    def test_update_port_add_additional_ip(self):
        pass

    def test_delete_ports_ignores_port_not_found(self):
        pass

    def test_delete_ports_by_device_id_second_call_failure(self):
        pass

    def test_delete_ports_by_device_id(self):
        pass

    def test_delete_port_public_network(self):
        pass

    def test_delete_port(self):
        pass


class TestContrailSecurityGroups(test_sg.TestSecurityGroups,
                                 JVContrailPluginTestCase):
    def setUp(self, plugin=None, ext_mgr=None):
        initialize_fakes()
        super(TestContrailSecurityGroups, self).setUp(self._plugin_name,
                                                      ext_mgr)
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)

    def tearDown(self):
        super(TestContrailSecurityGroups, self).tearDown()
        reset_fakes()

    def test_create_security_group_rule_with_unmasked_prefix(self):
        pass

    def test_create_security_group_rule_invalid_ethertype_for_prefix(self):
        pass

    def test_create_security_group_rule_icmp_with_code_only(self):
        pass
