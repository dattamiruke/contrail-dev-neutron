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

import neutron.db.api
from neutron.manager import NeutronManager
from neutron.tests.unit import test_db_plugin as test_plugin
from neutron.tests.unit import testlib_api



subnet_obj = {u'subnet':
              {'name': '', 'enable_dhcp': True,
               u'network_id': u'b11ffca3-3dfc-435e-ae0e-8f44da7188b7',
               'tenant_id': u'8162e75da480419a8b2ae7088dbc14f5',
               'dns_nameservers': '',
               u'contrail:ipam_fq_name':
               [u'default-domain', u'admin', u'default-network-ipam'],
               'allocation_pools': '', 'host_routes': '', u'ip_version': 4,
               'gateway_ip': '', u'cidr': u'20.20.1.0/29'}}

IIP_BREF_LIST = []
IIP_LIST = []
SUBNET_LIST = []
VM_LIST = []
VMI_LIST = []
VN_LIST = []
GLOBALPROJECTS = []


class MockVncApi(mock.MagicMock):
    def __init__(self, *args, **kwargs):
        pass

    def obj_to_id(self, *args, **kwargs):
        return args[0]._uuid
        return

    def kv_retrieve(self, *args, **kwargs):
        return []

    def kv_store(self, *args, **kwargs):
        return

    def kv_delete(self, *args, **kwargs):
        return

    def project_read(self, *args, **kwargs):
        return GLOBALPROJECTS[0]

    def projects_list(self, *args, **kwargs):
        return {'projects': [{'uuid': proj._uuid,
                              'fq_name': proj._fq_name}
                            for proj in GLOBALPROJECTS]}

    def subnet_create(self, subnet_obj):
        subnet_id = unicode(str(uuid.uuid4()))
        subnet_obj.set_uuid(subnet_id)
        SUBNET_LIST.append(subnet_obj)
        return subnet_id

    def subnet_read(self, id, *args, **kwargs):
        if len(SUBNET_LIST):
            for index in range(len(SUBNET_LIST)):
                if ((SUBNET_LIST[index].get_uuid()) == id):
                    return SUBNET_LIST[index]

    def subnets_list(self, *args, **kwargs):
        return {'subnets': [{'uuid': subnet._uuid,
                             'fq_name': subnet._fq_name}
                           for subnet in SUBNET_LIST]}

    def virtual_network_create(self, net_obj):
        net_id = unicode(str(uuid.uuid4()))
        net_obj.set_uuid(net_id)
        VN_LIST.append(net_obj)
        return net_id

    def virtual_network_read(self, id, *args, **kwargs):
        for vn in VN_LIST:
            if vn.get_uuid() == id:
                return vn

        #return a mock object if it is not created so far
        return MockVirtualNetwork('dummy-net', MockProject())

    def virtual_network_delete(self, id, *args, **kwargs):
        for vn in VN_LIST:
            if vn.get_uuid() == id:
                VN_LIST.remove(vn)
                return
        return

    def virtual_network_update(self, *args, **kwargs):
        return

    def virtual_networks_list(self, *args, **kwargs):
        return {'virtual-networks': [{'uuid': net.get_uuid(),
                                      'fq_name': net._fq_name}
                                    for net in VN_LIST]}

    def virtual_machine_create(self, mac_obj):
        mac_id = unicode(str(uuid.uuid4()))
        mac_obj.set_uuid(mac_id)
        VM_LIST.append(mac_obj)
        return mac_id

    def virtual_machine_read(self, id, *args, **kwargs):
        if len(VM_LIST):
            for index in range(len(VM_LIST)):
                if ((VM_LIST[index].get_uuid()) == id):
                    return VM_LIST[index]

    def virtual_machine_interface_create(self, vmi_obj):
        vmi_id = unicode(str(uuid.uuid4()))
        vmi_obj.set_uuid(vmi_id)
        VMI_LIST.append(vmi_obj)
        return vmi_id

    def virtual_machine_interface_delete(self, *args, **kwargs):
        return

    def virtual_machine_interface_update(self, *args, **kwargs):
        return

    def virtual_machine_interface_read(self, id, *args, **kwargs):
        if len(VMI_LIST):
            for index in range(len(VMI_LIST)):
                if ((VMI_LIST[index].get_uuid()) == id):
                    return VMI_LIST[index]

        #return a mock object if it is not created so far
        return MockVirtualMachineInterface('dummy-vmi', MockProject())

    def instance_ip_create(self, ip_obj):
        iip_id = unicode(str(uuid.uuid4()))
        ip_obj.set_uuid(iip_id)
        IIP_BREF_LIST.append({'uuid':iip_id})
        IIP_LIST.append(ip_obj)
        return iip_id

    def instance_ip_update(self):
        return

    def instance_ip_read(self, id, *args, **kwargs):
        if len(IIP_LIST):
            for index in range(len(IIP_LIST)):
                if ((IIP_LIST[index].get_uuid()) == id):
                    return IIP_LIST[index]

        #return a mock object if it is not created so far
        return MockInstanceIp('dummy-iip', MockProject())

    def instance_ip_delete(self, id):
        return


class MockVncObject(mock.MagicMock):
    def __init__(self, name=None, parent_obj=None, *args, **kwargs):
        super(MockVncObject, self).__init__()
        if not parent_obj:
            self._fq_name = [name]
        else:
            self._fq_name = parent_obj.get_fq_name() + [name]

        self._ipam_refs = [{'to': [u'default-domain', u'admin',
                           u'default-network-ipam']}]
        self._uuid = str(uuid.uuid4())
        self.name = name
        self.network_ipam_refs = []

    def set_uuid(self, uuid):
        self._uuid = uuid

    def get_uuid(self):
        return self._uuid

    def get_fq_name(self):
        return self._fq_name

    def get_network_ipam_refs(self):
        return getattr(self, 'network_ipam_refs', None)

    def add_network_ipam(self, ref_obj, ref_data):
        # refs = getattr(self, 'network_ipam_refs', [])
        refs = self.network_ipam_refs
        if not refs:
            self.network_ipam_refs = []

        # if ref already exists, update any attr with it
        for ref in refs:
            if ref['to'] == ref_obj.get_fq_name():
                ref = {'to': ref_obj.get_fq_name(), 'attr': ref_data}
                if ref_obj._uuid:
                    ref['uuid'] = ref_obj._uuid
                return

        # ref didn't exist before
        ref_info = {'to': ref_obj.get_fq_name(), 'attr': ref_data}
        if ref_obj._uuid:
            ref_info['uuid'] = ref_obj._uuid

        self.network_ipam_refs.append(ref_info)


class MockVirtualNetwork(MockVncObject):
    def __init__(self, name=None, parent_obj=None, *args, **kwargs):
        super(MockVncObject, self).__init__()
        if not parent_obj:
            self._fq_name = [name]
        else:
            self._fq_name = parent_obj.get_fq_name() + [name]

        self.uuid = str(uuid.uuid4())
        self._shared = False
        self.name = name
        self.network_ipam_refs = []

    @property
    def parent_uuid(self):
        return self.parent_obj.get_uuid()

    def get_uuid(self):
        return self.uuid

    def set_uuid(self, uuid):
        self.uuid = uuid

    def get_shared(self):
        return self._shared

    def set_shared(self, shared):
        self._shared = shared

    def get_network_ipam_refs(self):
        return getattr(self, 'network_ipam_refs', None)


class MockVirtualMachine(mock.MagicMock):
    def __init__(self, name=None, parent_obj=None, *args, **kwargs):
        super(MockVirtualMachine, self).__init__()
        if not parent_obj:
            self._fq_name = [name]
        else:
            self._fq_name = parent_obj.get_fq_name() + [name]

        self._uuid = str(uuid.uuid4())
        self.name = name

    @property
    def parent_uuid(self):
        return self.parent_obj.get_uuid()

    def get_uuid(self):
        return self._uuid

    def set_uuid(self, uuid):
        self._uuid = uuid


class MockVirtualMachineInterface(mock.MagicMock):
    def __init__(self, name=None, parent_obj=None, *args, **kwargs):
        super(MockVirtualMachineInterface, self).__init__()
        if not parent_obj:
            self._fq_name = [name]
        else:
            self._fq_name = parent_obj.get_fq_name() + [name]

        self.uuid = str(uuid.uuid4())
        self._name = name
        self.parent_name = None
        self.display_name = name
        self.mac_addresses_refs = []
        self._net_refs = []
        self._sg_list = []

    @property
    def parent_uuid(self):
        return self.parent_obj.get_uuid()

    def get_uuid(self):
        return self.uuid

    def set_uuid(self, uuid):
        self.uuid = uuid

    def get_name(self):
        return self._name

    def set_name(self, name):
        self._name = name

    def get_display_name(self):
        return self.display_name

    def set_display_name(self, display_name):
        self.display_name = display_name

    def get_virtual_network_refs(self):
        return self._net_refs

    def set_virtual_network(self, net):
        self._net_refs.append(net)

    def get_security_group_list(self):
        return self._sg_list

    def set_security_group_list(self, sg_list):
        self._sg_list = sg_list

    def get_virtual_machine_interface_mac_addresses(self):
        return self.mac_addresses_refs

    def set_virtual_machine_interface_mac_addresses(self, mac_addresses):
        self.mac_addresses_refs = mac_addresses

    def get_instance_ip_back_refs(self):
        return IIP_BREF_LIST

class MockInstanceIp(mock.MagicMock):
    def __init__(self, name=None, *args, **kwargs):
        super(MockInstanceIp, self).__init__()
        self.name = name
        self._vmi = None
        self._net = None
        self._ipaddr = "10.1.1.1"

    def get_uuid(self):
        return self.uuid

    def set_uuid(self, uuid):
        self.uuid = uuid

    def get_virtual_machine_interface(self):
        return self._vmi

    def set_virtual_machine_interface(self, vmi):
        self._vmi = vmi

    def get_virtual_network(self):
        return self._net

    def set_virtual_network(self, net):
        self._net = net

    def get_instance_ip_address(self):
        return self._ipaddr

    def set_instance_ip_address(self, ipaddr):
        self._ipaddr = ipaddr


class MockSubnetType(mock.MagicMock):
    def __init__(self, name=None, ip_prefix=None, ip_prefix_len=None,
                 *args, **kwargs):
        super(MockSubnetType, self).__init__()
        self.name = name
        self.ip_prefix = ip_prefix
        self.ip_prefix_len = ip_prefix_len
        self.enable_dhcp = False
        self.dns_nameservers = []
        self.host_routes = []
        self.allocation_pools = []

    def get_ip_prefix(self):
        return self.ip_prefix

    def set_ip_prefix(self, ip_prefix):
        self.ip_prefix = ip_prefix

    def get_ip_prefix_len(self):
        return self.ip_prefix_len

    def set_ip_prefix_len(self, ip_prefix_len):
        self.ip_prefix_len = ip_prefix_len

    def get_dhcp(self):
        return self.enable_dhcp

    def set_dhcp(self, flag):
        self.enable_dhcp = flag

    def get_dns_nameservers(self):
        return getattr(self, 'dns_nameservers', None)

    def set_dns_nameservers(self, dns_nameservers):
        self.dns_nameservers = dns_nameservers

    def get_host_routes(self):
        return getattr(self, 'host_routes', None)

    def set_host_routes(self, host_routes):
        self.host_routes = host_routes

    def get_allocation_pools(self):
        return getattr(self, 'allocation_pools', None)

    def add_allocation_pools(self, pool):
        allocation_pools = self.get_allocation_pools()
        if not allocation_pools:
            allocation_pools.append(pool)
            return 0

        cidr = netaddr.IPNetwork("%s/%s" %(pool['start'], pool['end']))
        for apool in allocation_pools:
            acidr = netaddr.IPNetwork("%s/%s" %(apool['start'], apool['end']))
            if cidr in acidr or acidr in cidr:
                return 1

        allocation_pools.append(pool)
        return 0

    def set_allocation_pools(self, allocation_pools):
        if allocation_pools:
            self.allocation_pools = allocation_pools
            return

        # Create an allocation pool
        pool = {}
        cidr = "%s/%s" %(self.ip_prefix, self.ip_prefix_len)
        start_ip = str(netaddr.IPNetwork(cidr).network + 1)
        pool['start'] = start_ip
        end_ip = str(netaddr.IPNetwork(cidr).broadcast - 2)
        pool['end'] = end_ip

        self.allocation_pools.append(pool)


class MockIpamSubnetType(mock.MagicMock):
    def __init__(self, name=None, subnet=None, default_gateway=None,
                 *args, **kwargs):
        super(mock.MagicMock, self).__init__()
        self.subnet = subnet
        self.default_gateway = default_gateway

    def get_subnet(self):
        return self.subnet

    def set_subnet(self, subnet):
        self.subnet = subnet

    def get_default_gateway(self):
        return self.default_gateway

    def set_default_gateway(self, default_gateway):
        self.default_gateway = default_gateway

    def validate_IpAddressType(self, value):
        pass


class MockVnSubnetsType(mock.MagicMock):
    def __init__(self, name=None, parent_obj=None, ipam_subnets=None,
                 *args, **kwargs):
        super(mock.MagicMock, self).__init__()
        self.ipam_subnets = []
        if ipam_subnets:
            #self.ipam_subnets = copy.deepcopy(ipam_subnets)
            self.ipam_subnets = ipam_subnets

    def get_ipam_subnets(self):
        return self.ipam_subnets

    def set_ipam_subnets(self, ipam_subnets):
        self.ipam_subnets = ipam_subnets

    def add_ipam_subnets(self, value):
        self.ipam_subnets.append(value)

    def insert_ipam_subnets(self, index, value):
        self.ipam_subnets[index] = value

    def delete_ipam_subnets(self, value):
        self.ipam_subnets.remove(value)


class MockNetworkIpam(mock.MagicMock):
    def __init__(self, name=None, parent_obj=None,
                 network_ipam_mgmt=None, id_perms=None,
                 *args, **kwargs):
        super(mock.MagicMock, self).__init__()
        self._type = 'default-network-ipam'
        self.name = name
        self._uuid = None
        if parent_obj:
            self.parent_type = parent_obj._type
            # copy parent's fq_name
            self._fq_name = list(parent_obj._fq_name)
            self._fq_name.append(name)
            if not parent_obj.get_network_ipams():
                parent_obj.network_ipams = []
            parent_obj.network_ipams.append(self)
        else:  # No parent obj specified
            self.parent_type = 'project'
            self._fq_name = [u'default-domain', u'default-project']
            self._fq_name.append(name)

        # property fields
        if network_ipam_mgmt:
            self.network_ipam_mgmt = network_ipam_mgmt
        if id_perms:
            self.id_perms = id_perms

    def get_fq_name(self):
        return self._fq_name


class MockProject(mock.MagicMock):
    def __init__(self, name=None, parent_obj=None, id_perms=None,
                 *args, **kwargs):
        super(mock.MagicMock, self).__init__()
        self._type = 'project'
        self._uuid = str(uuid.uuid4())
        self.parent_type = 'domain'
        self.name = name
        self._fq_name = [u'default-domain']
        self._fq_name.append(name)
        self.security_groups = []

    def get_fq_name(self):
        return self._fq_name

    def get_security_groups(self):
        return getattr(self, 'security_groups', None)

    def set_security_groups(self, security_groups):
        self.security_groups = security_groups


def GlobalProjectApi(project_name):
    for proj in GLOBALPROJECTS:
        if proj.get_fq_name()[-1] == project_name:
            return proj

    project = MockProject(name=project_name)
    GLOBALPROJECTS.append(project)

    return project


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
        #super(mock.MagicMock, self).__init__()
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
            net = {'q_api_data':vn, 'q_extra_data':{}}
            return MockRequestsResponse(200, json.dumps(net))

    return MockRequestsResponse(200, '')

def fake_create_network(network):
    net_id = unicode(str(uuid.uuid4()))
    network['id'] = net_id
    network['status'] = 'ACTIVE'
    network['subnets'] = []
    VN_LIST.append(network)
    net = {'q_api_data':network, 'q_extra_data':{}}
    return MockRequestsResponse(200, json.dumps(net))

def fake_update_network(net_id, network):
    for vn in VN_LIST:
        if vn['id'] == net_id:
            for key  in network:
                vn[key] = network[key]

            net = {'q_api_data':vn, 'q_extra_data':{}}
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
            net = {'q_api_data':vn, 'q_extra_data':{}}
            nets.append(net)
    return MockRequestsResponse(200, json.dumps(nets))

def fake_get_network_count():
    retval = json.dumps({'count': len(VN_LIST)})
    return MockRequestsResponse(200, retval)

def fake_handle_network_requests(context, data):
    operation = context['operation']

    #import pdb; pdb.set_trace()
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

    def _filters_is_present(self, filters, key_name, match_value):
        if filters:
            if key_name in filters:
                try:
                    filters[key_name].index(match_value)
                except ValueError:  # not in requested list
                    return False
            #elif len(filters.keys()) == 1:
            #    shared_val = filters.get('shared')
            #    if shared_val and shared_val[0]:
            #        return False

        return True

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
           return self.delete(data['id'])
        elif operation == 'READALL':
           return self.list(data['filters'])
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

    def delete(self, id):
        del self._store[self._type][id]
        return MockRequestsResponse(200, json.dumps(''))

    def list(self, filters):
        resources = self._store[self._type]
        ret_resources = []
        for res_id in resources:
            resource = resources[res_id]
            if not self._filters_is_present(filters, 'admin_state_up',
                                            resource.get('admin_state_up')):
                continue
            if not self._filters_is_present(filters, 'shared',
                                            resource.get('shared')):
                continue
            if not self._filters_is_present(filters, 'ip_version',
                                            resource.get('ip_version')):
                continue
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
                if (network_owned and 
                    port['device_owner'] == 'network:dhcp'):
                    ret_ports.append(port)
                elif (not network_owned and 
                      port['device_owner'] != 'network:dhcp'):
                    ret_ports.append(port)

        return ret_ports

    def create(self, req_network_data):
        network_data = copy.deepcopy(req_network_data)
        network_data['subnets'] = []
        response = super(FakeNetworks, self).create(network_data)
        
        return response

    def update(self, id, req_network_data):
        existing_network = self._store['network'][id]
        if (req_network_data.get('shared') == False and
            existing_network['shared'] == True):
            ports_on_network = self._ports_on_network(id, False)
            network_tenant_id = existing_network['tenant_id']
            for port in ports_on_network:
                if port['tenant_id'] != network_tenant_id:
                    exc_info = {'type': 'InvalidSharedSetting',
                                'name': existing_network['name']}
                    return MockRequestsResponse(409, json.dumps(exc_info))

        response = super(FakeNetworks, self).update(id, req_network_data)
        if req_network_data.get('shared') != None:
            for subnet_data in existing_network['subnets']:
                subnet_dict = self._store['subnet'][subnet_data['id']]
                subnet_dict['shared'] = req_network_data['shared']

        return response

    def delete(self, id):
        non_network_owned_ports = self._ports_on_network(id, False)
        if non_network_owned_ports:
            exc_info = {'type': 'NetworkInUse',
                        'network_id': id}
            return MockRequestsResponse(409, json.dumps(exc_info))

        network_owned_ports = self._ports_on_network(id, True)
        for port in network_owned_ports:
            del self._store['port'][port['id']]

        return super(FakeNetworks, self).delete(id)

    def list(self, filters):
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
        else: # gateway specified
            gateway_ip = gw
            if netaddr.IPAddress(gw) not in netaddr.IPNetwork(cidr):
                start_ip = str(netaddr.IPNetwork(cidr).network + 1)
                end_ip = str(netaddr.IPNetwork(cidr).broadcast - 1)
                alloc_pool = {'first_ip': start_ip,
                              'last_ip': end_ip}
                alloc_pools.append(alloc_pool)
            else: # gateway in cidr
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
        else: # alloc pools specified
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

    def delete(self, id):
        non_network_owned_ports = self._ports_on_subnet(id, False)
        if self._ports_on_subnet(id):
            exc_info = {'type': 'SubnetInUse',
                        'id': id}
            return MockRequestsResponse(409, json.dumps(exc_info))
            
        network_owned_ports = self._ports_on_subnet(id, True)
        for port in network_owned_ports:
            del self._store['port'][port['id']]

        network_id = self._store['subnet'][id]['network_id']
        rem_subnets = [sn for sn in self._store['network'][network_id]['subnets'] \
                          if sn['id'] != id]
        self._store['network'][network_id]['subnets'] = rem_subnets
        self._addr_mgmt.delete_subnet(id)
        response = super(FakeSubnets, self).delete(id)
        
        return response


class FakePorts(FakeResources):
    def __init__(self, addr_mgmt):
        super(FakePorts, self).__init__('port', addr_mgmt)
 
    def _ip_to_subnet_id(self, network_id, fixed_ip_dict):
        if fixed_ip_dict.get('subnet_id'):
            return (fixed_ip_dict['subnet_id'], fixed_ip_dict['ip_address'])

        for subnet in self._store['network'][network_id]['subnets']:
            if fixed_ip_dict['ip_address'] in netaddr.IPNetwork(subnet['cidr']):
                return (subnet['id'], fixed_ip_dict['ip_address'])

        return None, fixed_ip_dict['ip_address']

    def create(self, req_port_data):
        port_data = copy.deepcopy(req_port_data)
        if not port_data.get('id'):
            port_data['id'] = str(uuid.uuid4())

        req_fixed_ips = port_data['fixed_ips']
        if req_fixed_ips:
            for fixed_ip_dict in req_fixed_ips:
                if not self._addr_mgmt.is_ip_unique(fixed_ip_dict['subnet_id'],
                                                    fixed_ip_dict['ip_address']):
                    exc_info = {'type': 'IpAddressInUse',
                                'network_id': port_data['network_id'],
                                'ip_address': fixed_ip_dict['ip_address']}
                    return MockRequestsResponse(409, json.dumps(exc_info))
            for fixed_ip_dict in req_fixed_ips:
                subnet_id = fixed_ip_dict['subnet_id']
                address = fixed_ip_dict['ip_address']
                self._addr_mgmt.create_ip(subnet_id, address, port_data['id'])
        else:
            port_data['fixed_ips'] = []
            network_id = port_data['network_id']
            subnets = self._store['network'][network_id]['subnets']
            if subnets:
                subnet_id, address = self._addr_mgmt.alloc_ip(network_id, 
                                                         port_data['id'])
                if address:
                    self._addr_mgmt.create_ip(subnet_id, address, port_data['id'])
                    port_data['fixed_ips'] = [ {'subnet_id': subnet_id,
                                                'ip_address': address} ]
                else:
                    exc_info = {'type': 'IpAddressGenerationFailure',
                                'network_id': network_id}
                    return MockRequestsResponse(409, json.dumps(exc_info))

        response = super(FakePorts, self).create(port_data)
        return response

    def update(self, id, req_port_data):
        port_data = copy.deepcopy(req_port_data)
        existing_port = self._store['port'][id]
        
        req_fixed_ips = port_data.get('fixed_ips')
        if req_fixed_ips:
            network_id = existing_port['network_id']
            existing_ip_set = set([(e['subnet_id'], e['ip_address']) for e in existing_port['fixed_ips']])
            new_ip_set = set([self._ip_to_subnet_id(network_id, n) for n in req_fixed_ips])
            for ip_tuple in existing_ip_set - new_ip_set:
                self._addr_mgmt.delete_ip(ip_tuple[0], ip_tuple[1], existing_port['id'])
            for ip_tuple in new_ip_set - existing_ip_set:
                self._addr_mgmt.create_ip(ip_tuple[0], ip_tuple[1], existing_port['id'])

            port_ip_data = []
            for ip_tuple in new_ip_set:
                port_ip_data.append({'subnet_id':ip_tuple[0], 'ip_address':ip_tuple[1]})
            port_data['fixed_ips'] = port_ip_data

        response = super(FakePorts, self).update(id, port_data)
        return response

    def delete(self, id):
        existing_port = self._store['port'][id]
        response = super(FakePorts, self).delete(id)

        for fixed_ips in existing_port['fixed_ips']:
            self._addr_mgmt.delete_ip(fixed_ips['subnet_id'], fixed_ips['ip_address'], id)

        return response

    def list(self, filters):
        if 'fixed_ips' in filters:
            ret_ports = []
            ports = [self._store['port'][id] for id in self._store['port']]
            for port in ports:
                for fixed_ip in port.get('fixed_ips', []):
                    if (fixed_ip['subnet_id'] in filters['fixed_ips']['subnet_id'] and
                        fixed_ip['ip_address'] in filters['fixed_ips']['ip_address']):
                        ret_ports.append(port)
            return MockRequestsResponse(200, json.dumps(ret_ports))

        return super(FakePorts, self).list(filters)

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
                            'ip_to_port': {}})

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

    def alloc_ip(self, network_id, port_id):
        subnet_dicts = [self._subnet_dicts[sn_id] for sn_id in self._subnet_dicts
                              if self._subnet_dicts[sn_id]['network_id'] == network_id]
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
    #api_type = context['type']

    #if api_type == 'network':
    #   return fake_handle_network_requests(context, data)
    # Add more types here ...

def fake_requests_get(*args, **kwargs):
    import pdb; pdb.set_trace()

def fake_requests_put(*args, **kwargs):
    import pdb; pdb.set_trace()

def fake_requests_delete(*args, **kwargs):
    import pdb; pdb.set_trace()

fake_requests = mock.MagicMock(name='fake_requests_pkg')
sys.modules['requests'] = fake_requests
fake_requests.get = fake_requests_get
fake_requests.put = fake_requests_put
fake_requests.post = fake_requests_post
fake_requests.delete = fake_requests_delete

# Mock definations for different pkgs, modules and VncApi
mock_vnc_api_cls = mock.MagicMock(name='MockVncApi', side_effect=MockVncApi)
mock_vnc_api_mod = mock.MagicMock(name='vnc_api_mock_mod')
mock_vnc_api_mod.VncApi = mock_vnc_api_cls
mock_vnc_api_mod.VirtualNetwork = MockVirtualNetwork
mock_vnc_api_mod.VirtualMachine = MockVirtualMachine
mock_vnc_api_mod.VirtualMachineInterface = MockVirtualMachineInterface
mock_vnc_api_mod.SubnetType = MockSubnetType
mock_vnc_api_mod.IpamSubnetType = MockIpamSubnetType
mock_vnc_api_mod.VnSubnetsType = MockVnSubnetsType
mock_vnc_api_mod.NetworkIpam = MockNetworkIpam
mock_vnc_api_mod.InstanceIp = MockInstanceIp
mock_vnc_api_mod.Project = GlobalProjectApi

mock_vnc_api_pkg = mock.MagicMock(name='vnc_api_mock_pkg')
mock_vnc_api_pkg.vnc_api = mock_vnc_api_mod
mock_cfgm_common_mod = mock.MagicMock(name='cfgm_common_mock_mod')
mock_cfgm_exception_mod = mock.MagicMock(name='cfgm_exception_mock_mod')
sys.modules['neutron.plugins.juniper.contrail.ctdb.vnc_api'] = \
    mock_vnc_api_pkg
sys.modules['neutron.plugins.juniper.contrail.ctdb.vnc_api.vnc_api'] = \
    mock_vnc_api_mod
sys.modules['neutron.plugins.juniper.contrail.ctdb.cfgm_common'] = \
    mock_cfgm_common_mod
sys.modules[('neutron.plugins.juniper.contrail.ctdb.cfgm_common.'
             'exceptions')] = \
    mock_cfgm_exception_mod


CONTRAIL_PKG_PATH = "neutron.plugins.juniper.contrail.contrail_plugin_core"


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

    def setUp(self):

        cfg.CONF.keystone_authtoken = keystone_info_class()
        mock_cfgm_common_mod.exceptions = mock_cfgm_exception_mod

        mock_vnc_api_mod.common = mock_cfgm_common_mod
        mock_vnc_api_mod.VncApi = mock_vnc_api_cls

        mock_vnc_api_pkg.vnc_api = mock_vnc_api_mod

        super(JVContrailPluginTestCase, self).setUp(self._plugin_name)
        cfg.CONF.set_override('quota_driver', 'neutron.quota.ConfDriver',
                              group='QUOTAS')
        self._tenant_id = GlobalProjectApi(self._tenant_id)._uuid
        neutron.db.api._ENGINE = mock.MagicMock()

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


class TestContrailPortsV2(test_plugin.TestPortsV2,
                          JVContrailPluginTestCase):
    def setUp(self):
        initialize_fakes()
        super(TestContrailPortsV2, self).setUp()

    def tearDown(self):
        super(TestContrailPortsV2, self).tearDown()
        reset_fakes()

    def test_update_port_update_ip_address_only(self):
        pass

    def test_mac_exhaustion(self):
        pass

    def test_create_port_bad_tenant(self):
        pass

    def test_recycle_ip_address_on_exhausted_allocation_pool(self):
        pass
    def test_mac_generation_4octet(self):
        pass
    def test_requested_ips_only(self):
        pass
    def test_update_port_add_additional_ip(self):
        pass
    def test_mac_generation(self):
        pass
    def test_range_allocation(self):
        pass
    def test_update_fixed_ip_lease_expiration_invalid_address(self):
        pass
    def test_requested_subnet_id_v4_and_v6(self):
        pass
    def test_requested_duplicate_mac(self):
        pass
    def test_recycle_ip_address_in_allocation_pool(self):
        pass
    def test_requested_subnet_id(self):
        pass
    def test_recycle_ip_address_outside_allocation_pool(self):
        pass
#   def test_create_port_json(self):
#       ##
#       pass
#
#   def test_create_port_bad_tenant(self):
#       ## - 403 vs 404
#       pass
#
#   def test_create_port_public_network(self):
#       ## - tenant id is a name
#       pass
#
#   def test_create_port_public_network_with_ip(self):
#       ##
#       pass
#
#   def test_create_ports_bulk_emulated(self):
#       ##
#       pass
#
#   def test_create_ports_bulk_wrong_input(self):
#       ##
#       pass
#
#   def test_create_port_as_admin(self):
#       ##
#       pass
#
#   def test_list_ports(self):
#       ##
#       pass
#
#   def test_list_ports_filtered_by_fixed_ip(self):
#       ##
#       pass
#
#   def test_list_ports_public_network(self):
#       ##
#       pass
#
#   def test_list_ports_with_pagination_emulated(self):
#       ##
#       pass
#
#   def test_list_ports_with_pagination_reverse_emulated(self):
#       ##
#       pass
#
#   def test_list_ports_with_sort_emulated(self):
#       ##
#       pass
#
#   def test_delete_port(self):
#       ## - tenant id is a name ???
#       pass
#
#   def test_delete_port_public_network(self):
#       ## - tenant id is a name ???
#       pass
#
#   def test_update_port_update_ip(self):
#       ##
#       pass
#
#   def test_update_port_delete_ip(self):
#       ##
#       pass
#
#   def test_update_port_update_ip_address_only(self):
#       ##
#       pass
#
#   def test_update_port_update_ips(self):
#       ##
#       pass
#
#   def test_update_port_add_additional_ip(self):
#       ##
#       pass
#
#   def test_update_port_not_admin(self):
#       ##
#       pass
#
#   def test_delete_network_if_port_exists(self):
#       ##
#       pass
#
#   def test_no_more_port_exception(self):
#       ##
#       pass
#
#   def test_requested_duplicate_mac(self):
#       ##
#       pass
#
#   def test_mac_generation(self):
#       ##
#       pass
#
#   def test_mac_generation_4octet(self):
#       ##
#       pass
#
#   def test_mac_exhaustion(self):
#       ##
#       pass
#
#   def test_requested_duplicate_ip(self):
#       ##
#       pass
#
#   def test_requested_subnet_delete(self):
#       ##
#       pass
#
#   def test_requested_subnet_id(self):
#       ##
#       pass
#
#   def test_requested_subnet_id_not_on_network(self):
#       ##
#       pass
#
#   def test_requested_subnet_id_v4_and_v6(self):
#       ##
#       pass
#
#   def test_range_allocation(self):
#       self.skipTest("Plugin does not support Neutron allocation process")
#
#   def test_requested_invalid_fixed_ips(self):
#       ##
#       pass
#
#   def test_requested_split(self):
#       ## - valid IP Address ???
#       pass
#
#   def test_requested_ips_only(self):
#       ##
#       pass
#
#   def test_max_fixed_ips_exceeded(self):
#       ##
#       pass
#
#   def test_update_max_fixed_ips_exceeded(self):
#       ##
#       pass

