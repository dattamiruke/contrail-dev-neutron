# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2014 Juniper Networks.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# @author: Hampapur Ajay, Praneet Bachheti, Rudra Rugge, Atul Moghe

import copy
import logging
import ConfigParser
from pprint import pformat

from neutron.api.v2 import attributes as attr
from neutron.manager import NeutronManager
from neutron.common import exceptions as exc
from neutron.db import db_base_plugin_v2
from neutron.db import portbindings_base
from neutron.db import l3_db
from neutron.extensions import l3, securitygroup, vpcroutetable, external_net
from neutron.extensions import portbindings
from neutron.openstack.common import importutils
from neutron.openstack.common import jsonutils as json
from neutron.openstack.common import log as logging

from oslo.config import cfg
from httplib2 import Http
import netaddr
import re
import requests
import string
import sys
import cgitb

import ctdb.config_db

LOG = logging.getLogger(__name__)

vnc_opts = [
    cfg.StrOpt('api_server_ip', default='127.0.0.1',
               help='VNC IP address to connect to'),
    cfg.StrOpt('api_server_port', default='8082',
               help='VNC port to connect to'),
    cfg.BoolOpt('multi_tenancy', default=False,
                help='Multi Tenancy support'),
    cfg.StrOpt('contrail_extensions', default='',
                help='Contrail extensions support'),
    cfg.IntOpt('max_retries', default=-1,
               help='Maximum retries to connect to VNC Server'),
    cfg.IntOpt('retry_interval', default=3,
               help='Retry Interval to connect to VNC Server'),
]


class NeutronPluginContrailCoreV2(db_base_plugin_v2.NeutronDbPluginV2,
                     securitygroup.SecurityGroupPluginBase,
                     portbindings_base.PortBindingBaseMixin,
                     l3_db.L3_NAT_db_mixin,
                     external_net.External_net):

    # agent extension is added to avoid return 404 for get_agents
    supported_extension_aliases = ["security-group", "router", "route-table",
                                   "port-security", "binding", "agent",
                                   "quotas", "external-net"]
    _cfgdb = None
    _args = None
    _tenant_id_dict = {}
    _tenant_name_dict = {}
    PLUGIN_URL_PREFIX = '/neutron'

    @classmethod
    def _parse_class_args(cls):
        cls._multi_tenancy = cfg.CONF.APISERVER.multi_tenancy

        # contrail extension format:
        #  contrail_extensions=ipam:<classpath>,policy:<classpath>
        ext_aliases = NeutronPluginContrailCoreV2.supported_extension_aliases
        cls._contrail_extensions_class = []
        contrail_exts_conf = cfg.CONF.APISERVER.contrail_extensions
        if contrail_exts_conf:
            supp_exts = contrail_exts_conf.split(",")
            for supp_ext in supp_exts:
                ext_vars = supp_ext.split(":")
                ext_aliases.append(ext_vars[0])
                cls._contrail_extensions_class.append(
                    importutils.import_class(ext_vars[1])())

        cls._max_retries = cfg.CONF.APISERVER.max_retries
        cls._retry_interval = cfg.CONF.APISERVER.retry_interval

        keystone_conf = cfg.CONF.keystone_authtoken
        cls._admin_token = keystone_conf.admin_token
        cls._auth_url = ('%s://%s:%s/v2.0/' %
                         (keystone_conf.auth_protocol,
                          keystone_conf.auth_host,
                          keystone_conf.auth_port))
        cls._admin_user = keystone_conf.admin_user
        cls._admin_password = keystone_conf.admin_password
        cls._admin_tenant_name = keystone_conf.admin_tenant_name
        cls._tenants_api = '%s/tenants' % (cls._auth_url)

    @classmethod
    def _connect_to_db(cls):
        """
        Many instantiations of plugin (base + extensions) but need to have
        only one config db conn (else error from ifmap-server)
        """
        cls._cfgdb_map = {}
        if cls._cfgdb is None:
            # Initialize connection to DB and add default entries
            cls._cfgdb = ctdb.config_db.DBInterface(
                cls._admin_user,
                cls._admin_password,
                cls._admin_tenant_name,
                cfg.CONF.APISERVER.api_server_ip,
                cfg.CONF.APISERVER.api_server_port)
            cls._cfgdb.manager = cls

    @classmethod
    def _get_user_cfgdb(cls, context):
        if not cls._multi_tenancy:
            return cls._cfgdb
        user_id = context.user_id
        role = string.join(context.roles, ",")
        if not user_id in cls._cfgdb_map:
            cls._cfgdb_map[user_id] = ctdb.config_db.DBInterface(
                cls._admin_user, cls._admin_password, cls._admin_tenant_name,
                cfg.CONF.APISERVER.api_server_ip,
                cfg.CONF.APISERVER.api_server_port,
                user_info={'user_id': user_id, 'role': role})
            cls._cfgdb_map[user_id].manager = cls

        return cls._cfgdb_map[user_id]

    @classmethod
    def _tenant_list_from_keystone(cls):
        # get all tenants
        headers = {'X-Auth-Token': cls._admin_token,
                   'Content-Type': 'application/json'}
        try:
            response, content = Http().request(cls._tenants_api,
                                               method="GET",
                                               headers=headers)
            if response.status != 200:
                return
        except Exception:
            return

        # transform needed for python compatibility
        content = json.loads(content)

        # bail if response is unexpected
        if 'tenants' not in content:
            return

        # create a dictionary for id->name and name->id mapping
        for tenant in content['tenants']:
            print 'Adding tenant %s:%s to cache' % (tenant['name'],
                                                    tenant['id'])
            cls._tenant_id_dict[tenant['id']] = tenant['name']
            cls._tenant_name_dict[tenant['name']] = tenant['id']

    def __init__(self):
        cfg.CONF.register_opts(vnc_opts, 'APISERVER')

        NeutronPluginContrailCoreV2._parse_class_args()

        NeutronPluginContrailCoreV2._connect_to_db()
        self._cfgdb = NeutronPluginContrailCoreV2._cfgdb

        NeutronPluginContrailCoreV2._tenant_list_from_keystone()

        self.base_binding_dict = self._get_base_binding_dict()
        portbindings_base.register_port_dict_function()

    @classmethod
    def __getattr__(cls, name):
        for extension_class in cls._contrail_extensions_class:
            try:
                return getattr(extension_class, name)
            except AttributeError:
                pass

        raise AttributeError()

    def _get_base_binding_dict(self):
        binding = {
            portbindings.VIF_TYPE: portbindings.VIF_TYPE_VROUTER,
            portbindings.CAPABILITIES: {
                portbindings.CAP_PORT_FILTER:
                'security-group' in self.supported_extension_aliases}}
        return binding

    @classmethod
    def tenant_id_to_name(cls, id):
        # bail if we never built the list successfully
        if len(cls._tenant_id_dict) == 0:
            return id
        # check cache
        if id in cls._tenant_id_dict:
            return cls._tenant_id_dict[id]
        # otherwise refresh
        cls._tenant_list_from_keystone()
        # second time's a charm?
        return cls._tenant_id_dict[id] if id in cls._tenant_id_dict else id

    @classmethod
    def tenant_name_to_id(cls, name):
        # bail if we never built the list successfully
        if len(cls._tenant_name_dict) == 0:
            return name
        # check cache
        if name in cls._tenant_name_dict:
            return cls._tenant_name_dict[name]
        # otherwise refresh
        cls._tenant_list_from_keystone()
        # second time's a charm?
        if name in cls._tenant_name_dict:
            return cls._tenant_name_dict[name]
        else:
            return name

    # Return empty list of agents.
    def get_agents(self, context, filters=None, fields=None):
        agents = []
        return agents;

    # Helper routines
    def _request_api_server(self, url, method, data=None, headers=None):
        if method == 'GET':
            return requests.get(url)
        if method == 'POST':
            return requests.post(url, data=data, headers=headers)
        if method == 'DELETE':
            return requests.delete(url)

    def _relay_request(self, method, url_path, data=None):
        """
        Send received request to api server
        """
        # make url, add api server address/port
        url = "http://%s:%s%s" % (cfg.CONF.APISERVER.api_server_ip,
                                  cfg.CONF.APISERVER.api_server_port,
                                  url_path)

        return self._request_api_server(
            url, method, data=data,
            headers={'Content-type': 'application/json'})

    def _request_backend(self, context, data_dict, obj_name, action):
        context_dict = self._encode_context(context, action, obj_name)
        data = json.dumps({'context':context_dict, 'data':data_dict})

        url_path = "%s/%s" % (self.PLUGIN_URL_PREFIX, obj_name)
        response = self._relay_request('POST', url_path, data=data)
        if response.content:
            return response.status_code, json.loads(response.content)

    def _encode_context(self, context, operation, apitype):
        cdict = {}
        cdict['user_id'] = getattr(context, 'user_id', '')
        if context.roles:
            cdict['roles'] = context.roles
        if context.tenant:
            cdict['tenant'] = context.tenant
        cdict['is_admin'] = getattr(context, 'is_admin', False)
        cdict['operation'] = operation
        cdict['type'] = apitype
        cdict['tenant_id'] = getattr(context, 'tenant_id', None)
        return cdict

    def _encode_resource(self, resource_id=None, resource=None, fields=None,
                        filters=None):
        resource_dict = {}
        if id:
            resource_dict['id'] = resource_id
        if resource:
            resource_dict['resource'] = resource
        resource_dict['filters'] = filters
        resource_dict['fields'] = fields
        return resource_dict

    def _transform_response(self, status_code, info=None, info_list=None, fields=None, obj_name=None):
        funcname = "_make_" + obj_name + "_dict"
        func = getattr(self, funcname)

        info_dicts = []
        if info:
            info_dicts = func(info, status_code, fields)
        else: 
            for entry in info_list:
                info_dict = func(entry, status_code, fields)
                info_dicts.append(info_dict)

        return info_dicts

    def _create_resource(self, res_type, context, res_data):
        res_dict = self._encode_resource(resource=res_data[res_type])
        status_code, res_info = self._request_backend(context, res_dict, res_type, 'CREATE')
        res_dicts = self._transform_response(status_code, info=res_info, obj_name=res_type)

        return res_dicts

    def _get_resource(self, res_type, context, id, fields):
        res_dict = self._encode_resource(resource_id=id, fields=fields)
        status_code, res_info = self._request_backend(context, res_dict, res_type, 'READ')
        res_dicts = self._transform_response(status_code, info=res_info, fields=fields, 
                                             obj_name=res_type)

        return res_dicts

    def _update_resource(self, res_type, context, id, res_data):
        res_dict = self._encode_resource(resource_id=id, resource=res_data[res_type])
        status_code, res_info = self._request_backend(context, res_dict, res_type, 'UPDATE')
        res_dicts = self._transform_response(status_code, info=res_info, obj_name=res_type)

        return res_dicts

    def _delete_resource(self, res_type, context, id):
        res_dict = self._encode_resource(resource_id=id)
        return self._request_backend(context, res_dict, res_type, 'DELETE')

    def _list_resource(self, res_type, context, filters, fields):
        res_dict = self._encode_resource(filters=filters, fields=fields)
        status_code, res_info = self._request_backend(context, res_dict, res_type, 'READALL')
        res_dicts = self._transform_response(status_code, info_list=res_info, fields=fields,
                                             obj_name=res_type)

        return res_dicts

    def _count_resource(self, res_type, context, filters):
        res_dict = self._encode_resource(filters=filters)
        status_code, res_count = self._request_backend(context, res_dict, res_type,
            'READCOUNT')

        return res_count

    # Network API handlers
    def _make_network_dict(self, entry, status_code=None, fields=None):
        if status_code == 200:
            return super(NeutronPluginContrailCoreV2, self)._make_network_dict(entry, fields)

        if entry['type'] == 'InvalidSharedSetting':
            raise exc.InvalidSharedSetting(network=entry['name'])
        if entry['type'] == 'NetworkInUse':
            raise exc.NetworkInUse(net_id=entry['id'])

    def _get_network(self, context, id):
        network_dict = self._get_resource('network', context, id, None)
        return network_dict

    def create_network(self, context, network):
        """
        Creates a new Virtual Network, and assigns it
        a symbolic name.
        """
        tenant_id = self._get_tenant_id_for_create(context, network['network'])

        plugin_network = copy.deepcopy(network)
        if network['network']['router:external'] == attr.ATTR_NOT_SPECIFIED:
            del plugin_network['network']['router:external']

        network_dicts = self._create_resource('network', context,
                                              plugin_network)

        LOG.debug("create_network(): " + pformat(network_dicts) + "\n")
        return network_dicts

    def get_network(self, context, network_id, fields=None):
        """
        Get the attributes of a particular Virtual Network.
        """
        network_dicts = self._get_resource('network', context, network_id, fields)

        LOG.debug("get_network(): " + pformat(network_dicts))
        return self._fields(network_dicts, fields)

    def update_network(self, context, network_id, network):
        """
        Updates the attributes of a particular Virtual Network.
        """
        plugin_network = copy.deepcopy(network)
        network_dicts = self._update_resource('network', context, network_id,
                                              plugin_network)

        LOG.debug("update_network(): " + pformat(network_dicts))
        return network_dicts

    def delete_network(self, context, network_id):
        """
        Deletes the network with the specified network identifier
        belonging to the specified tenant.
        """
        status_code, msg = self._delete_resource('network', context, network_id)

        LOG.debug("delete_network(): %s" % (network_id))
        if status_code == 200:
            return 
        elif status_code == 409:
            raise exc.NetworkInUse(net_id=network_id)

    def get_networks(self, context, filters=None, fields=None):
        """
        Get the list of Virtual Networks.
        """
        network_dicts = self._list_resource('network', context, filters, fields)

        LOG.debug(
            "get_networks(): filters: " + pformat(filters) + " data: "
            + pformat(network_dicts))
        return network_dicts

    def get_networks_count(self, context, filters=None):
        """
        Get the count of Virtual Network.
        """
        networks_count = self._count_resource('network', context, filters)

        LOG.debug("get_networks_count(): filters: " + pformat(filters) + " data: " + str(networks_count['count']))
        return networks_count['count']

    # Subnet API handlers
    def _make_subnet_dict(self, entry, status_code=None, fields=None):
        if status_code == 200:
            return super(NeutronPluginContrailCoreV2, self)._make_subnet_dict(entry, fields)

        if entry['type'] == 'SubnetInUse':
            raise exc.SubnetInUse(subnet_id=entry['id'])
        if entry['type'] == 'GatewayConflictWithAllocationPools':
            pool_range = netaddr.IPRange(entry['pool']['start'],
                                         entry['pool']['end'])
            gateway_ip = entry['ip_address']
            raise exc.GatewayConflictWithAllocationPools(pool=pool_range,
                                                         ip_address=gateway_ip)
        if entry['type'] == 'SubnetNotFound':
            raise exc.SubnetNotFound(subnet_id=entry['id'])

    def _get_subnet(self, context, id):
        subnet_dict = self._get_resource('subnet', context, id, None)
        return subnet_dict

    def _get_all_subnets(self, context):
        all_networks = self.get_networks(context)
        all_subnets = []
        for network in all_networks:
            subnets = [self._get_subnet(context, id) for id in network['subnets']]
            all_subnets.extend(subnets)

        return all_subnets

    def _validate_subnet_cidr(self, context, network, new_subnet_cidr):
        """Validate the CIDR for a subnet.

        Verifies the specified CIDR does not overlap with the ones defined
        for the other subnets specified for this network, or with any other
        CIDR if overlapping IPs are disabled.
        """
        new_subnet_ipset = netaddr.IPSet([new_subnet_cidr])
        if cfg.CONF.allow_overlapping_ips:
            subnet_ids = network['subnets']
            subnet_list = [self._get_subnet(context, id) for id in subnet_ids]
        else:
            subnet_list = self._get_all_subnets(context)

        for subnet in subnet_list:
            if (netaddr.IPSet([subnet['cidr']]) & new_subnet_ipset):
                # don't give out details of the overlapping subnet
                err_msg = (_("Requested subnet with cidr: %(cidr)s for "
                             "network: %(network_id)s overlaps with another "
                             "subnet") %
                           {'cidr': new_subnet_cidr,
                            'network_id': network['id']})
                LOG.error(_("Validation for CIDR: %(new_cidr)s failed - "
                            "overlaps with subnet %(subnet_id)s "
                            "(CIDR: %(cidr)s)"),
                          {'new_cidr': new_subnet_cidr,
                           'subnet_id': subnet['id'],
                           'cidr': subnet['cidr']})
                raise exc.InvalidInput(error_message=err_msg)

    def create_subnet(self, context, subnet):
        """
        Creates a new subnet, and assigns it a symbolic name.
        """
        tenant_id = self._get_tenant_id_for_create(context, subnet['subnet'])

        plugin_subnet = copy.deepcopy(subnet)
        if subnet['subnet']['dns_nameservers'] == attr.ATTR_NOT_SPECIFIED:
            plugin_subnet['subnet']['dns_nameservers'] = None
        if subnet['subnet']['allocation_pools'] == attr.ATTR_NOT_SPECIFIED:
            plugin_subnet['subnet']['allocation_pools'] = None
        if subnet['subnet']['gateway_ip'] == attr.ATTR_NOT_SPECIFIED:
            plugin_subnet['subnet']['gateway_ip'] = None
        if subnet['subnet']['gateway_ip'] == None:
            plugin_subnet['subnet']['gateway_ip'] = '0.0.0.0'
        if subnet['subnet']['host_routes'] == attr.ATTR_NOT_SPECIFIED:
            plugin_subnet['subnet']['host_routes'] = None
        elif (len(subnet['subnet']['host_routes']) > 
              cfg.CONF.max_subnet_host_routes):
                raise exc.HostRoutesExhausted(
                    subnet_id=subnet['subnet'].get('id', _('new subnet')),
                    quota=cfg.CONF.max_subnet_host_routes)

        self._validate_subnet(context, plugin_subnet['subnet'])
        if plugin_subnet['subnet']['allocation_pools']:
            self._validate_allocation_pools(plugin_subnet['subnet']['allocation_pools'],
                                            plugin_subnet['subnet']['cidr'])
        #import pdb; pdb.set_trace()
        if (plugin_subnet['subnet']['gateway_ip'] and 
            plugin_subnet['subnet']['allocation_pools']):
            self._validate_gw_out_of_pools(plugin_subnet['subnet']['gateway_ip'],
                                           plugin_subnet['subnet']['allocation_pools'])
        network = self._get_network(context, plugin_subnet['subnet']['network_id'])
        self._validate_subnet_cidr(context, network, plugin_subnet['subnet']['cidr'])

        subnet_dicts = self._create_resource('subnet', context, plugin_subnet)
        LOG.debug("create_subnet(): " + pformat(subnet_dicts) + "\n")

        return subnet_dicts

    def get_subnet(self, context, subnet_id, fields=None):
        """
        Get the attributes of a particular subnet.
        """
        subnet_dicts = self._get_resource('subnet', context, subnet_id, fields)

        LOG.debug("get_subnet(): " + pformat(subnet_dicts))
        return subnet_dicts

    def update_subnet(self, context, subnet_id, subnet):
        """
        Updates the attributes of a particular subnet.
        """
        plugin_subnet = copy.deepcopy(subnet)
        existing_subnet = self._get_subnet(context, subnet_id)
        # for self._validate these fields are needed
        plugin_subnet['subnet']['ip_version'] = existing_subnet['ip_version']
        plugin_subnet['subnet']['cidr'] = existing_subnet['cidr']
        plugin_subnet['subnet']['id'] = existing_subnet['id']
        self._validate_subnet(context, plugin_subnet['subnet'])
        if ('gateway_ip' in plugin_subnet['subnet'] and 
            plugin_subnet['subnet']['gateway_ip']):
            self._validate_gw_out_of_pools(plugin_subnet['subnet']['gateway_ip'],
                                           existing_subnet['allocation_pools'])


        subnet_dicts = self._update_resource('subnet', context, subnet_id,
                                             plugin_subnet)

        LOG.debug("update_subnet(): " + pformat(subnet_dicts))
        return subnet_dicts

    def delete_subnet(self, context, subnet_id):
        """
        Deletes the subnet with the specified subnet identifier
        belonging to the specified tenant.
        """
        status_code, msg = self._delete_resource('subnet', context, subnet_id)

        LOG.debug("delete_subnet(): %s" % (subnet_id))
        if status_code == 200:
            return
        elif status_code == 409:
            raise exc.SubnetInUse(subnet_id=subnet_id)

    def get_subnets(self, context, filters=None, fields=None):
        """
        Get the list of subnets
        """
        subnet_dicts = self._list_resource('subnet', context, filters, fields)

        LOG.debug(
            "get_subnets(): filters: " + pformat(filters) + " data: "
            + pformat(subnet_dicts))
        return subnet_dicts

    def get_subnets_count(self, context, filters=None):
        """
        Get the count of subnets.
        """
        subnets_count = self._count_resource('subnet', context, filters)

        LOG.debug("get_subnets_count(): filters: " + pformat(filters) +
                  " data: " + str(subnets_count['count']))
        return subnets_count['count']

    def _make_port_dict(self, entry, status_code=None, fields=None):
        if status_code == 200:
            port_dict = super(NeutronPluginContrailCoreV2, self)._make_port_dict(
                entry, fields)
            self._process_portbindings_create_and_update(None, entry,
                                                         port_dict)
            return port_dict

        if entry['type'] == 'IpAddressInUse':
            raise exc.IpAddressInUse(net_id=entry['network_id'],
                                     ip_address=entry['ip_address'])
        if entry['type'] == 'IpAddressGenerationFailure':
            raise exc.IpAddressGenerationFailure(net_id=entry['network_id'])

    def _extend_port_dict_security_group(self, port_res, port_db):
        # Security group bindings will be retrieved from the sqlalchemy
        # model. As they're loaded eagerly with ports because of the
        # joined load they will not cause an extra query.
        port_res[securitygroup.SECURITYGROUPS] = port_db.get('security_groups', []) or []
        return port_res

    def _get_port(self, context, id):
        port_dict = self._get_resource('port', context, id, None)
        return port_dict

    def _test_fixed_ips_for_port(self, context, network_id, fixed_ips):
        """Test fixed IPs for port.

        Check that configured subnets are valid prior to allocating any
        IPs. Include the subnet_id in the result if only an IP address is
        configured.

        :raises: InvalidInput, IpAddressInUse
        """
        fixed_ip_set = []
        for fixed in fixed_ips:
            found = False
            if 'subnet_id' not in fixed:
                if 'ip_address' not in fixed:
                    msg = _('IP allocation requires subnet_id or ip_address')
                    raise exc.InvalidInput(error_message=msg)

                filter = {'network_id': [network_id]}
                subnets = self.get_subnets(context, filters=filter)
                for subnet in subnets:
                    if super(NeutronPluginContrailCoreV2, self)._check_subnet_ip(subnet['cidr'],
                                                          fixed['ip_address']):
                        found = True
                        subnet_id = subnet['id']
                        break
                if not found:
                    msg = _('IP address %s is not a valid IP for the defined '
                            'networks subnets') % fixed['ip_address']
                    raise exc.InvalidInput(error_message=msg)
            else:
                subnet = self._get_subnet(context, fixed['subnet_id'])
                if subnet['network_id'] != network_id:
                    msg = (_("Failed to create port on network %(network_id)s"
                             ", because fixed_ips included invalid subnet "
                             "%(subnet_id)s") %
                           {'network_id': network_id,
                            'subnet_id': fixed['subnet_id']})
                    raise exc.InvalidInput(error_message=msg)
                subnet_id = subnet['id']

            if 'ip_address' in fixed:
                # Ensure that the IP is valid on the subnet
                if (not found and
                    not super(NeutronPluginContrailCoreV2, self)._check_subnet_ip(
                        subnet['cidr'], fixed['ip_address'])):
                    msg = _('IP address %s is not a valid IP for the defined '
                            'subnet') % fixed['ip_address']
                    raise exc.InvalidInput(error_message=msg)

                fixed_ip_set.append({'subnet_id': subnet_id,
                                     'ip_address': fixed['ip_address']})
            else:
                fixed_ip_set.append({'subnet_id': subnet_id})
        if len(fixed_ip_set) > cfg.CONF.max_fixed_ips_per_port:
            msg = _('Exceeded maximim amount of fixed ips per port')
            raise exc.InvalidInput(error_message=msg)
        return fixed_ip_set

    def _update_ips_for_port(self, context, network_id, port_id, original_ips,
                             new_ips):
        """Add or remove IPs from the port."""
        ips = []
        # These ips are still on the port and haven't been removed
        prev_ips = []

        # the new_ips contain all of the fixed_ips that are to be updated
        if len(new_ips) > cfg.CONF.max_fixed_ips_per_port:
            msg = _('Exceeded maximim amount of fixed ips per port')
            raise exc.InvalidInput(error_message=msg)

        # Remove all of the intersecting elements
        for original_ip in original_ips[:]:
            for new_ip in new_ips[:]:
                if ('ip_address' in new_ip and
                    original_ip['ip_address'] == new_ip['ip_address']):
                    original_ips.remove(original_ip)
                    new_ips.remove(new_ip)
                    prev_ips.append(original_ip)

        # Check if the IP's to add are OK
        self._test_fixed_ips_for_port(context, network_id, new_ips)

        return new_ips, prev_ips

    def create_port(self, context, port):
        """
        Creates a port on the specified Virtual Network.
        """
        tenant_id = self._get_tenant_id_for_create(context, port['port'])

        plugin_port = copy.deepcopy(port)
        if port['port']['port_security_enabled'] == attr.ATTR_NOT_SPECIFIED:
            plugin_port['port']['port_security_enabled'] = None
        if port['port']['binding:host_id'] == attr.ATTR_NOT_SPECIFIED:
            plugin_port['port']['binding:host_id'] = None
        if port['port']['mac_address'] == attr.ATTR_NOT_SPECIFIED:
            plugin_port['port']['mac_address'] = None
        if port['port']['binding:profile'] == attr.ATTR_NOT_SPECIFIED:
            plugin_port['port']['binding:profile'] = None
        if port['port']['fixed_ips'] == attr.ATTR_NOT_SPECIFIED:
            plugin_port['port']['fixed_ips'] = None
        if port['port']['security_groups'] == attr.ATTR_NOT_SPECIFIED:
            del plugin_port['port']['security_groups']

        if plugin_port['port']['fixed_ips']:
            self._test_fixed_ips_for_port(context,
                                          plugin_port['port']['network_id'],
                                          plugin_port['port']['fixed_ips'])

        port_dicts = self._create_resource('port', context, plugin_port)
        LOG.debug("create_port(): " + pformat(port_dicts) + "\n")

        return port_dicts

    def get_port(self, context, port_id, fields=None):
        """
        Get the attributes of a particular port.
        """
        port_dicts = self._get_resource('port', context, port_id, fields)

        LOG.debug("get_port(): " + pformat(port_dicts))
        return port_dicts

    def update_port(self, context, port_id, port):
        """
        Updates the attributes of a port on the specified Virtual Network.
        """
        plugin_port = copy.deepcopy(port)
 
        if 'fixed_ips' in plugin_port['port']:
            original = self._get_port(context, port_id)
            added_ips, prev_ips = self._update_ips_for_port(
                context, original['network_id'], port_id,
                original['fixed_ips'], plugin_port['port']['fixed_ips'])
            plugin_port['port']['fixed_ips'] = prev_ips + added_ips

        port_dicts = self._update_resource('port', context, port_id,
                                           plugin_port)

        LOG.debug("update_port(): " + pformat(port_dicts))
        return port_dicts

    def delete_port(self, context, port_id):
        """
        Deletes a port on a specified Virtual Network,
        if the port contains a remote interface attachment,
        the remote interface is first un-plugged and then the port
        is deleted.
        """
        self._delete_resource('port', context, port_id)

        LOG.debug("delete_port(): %s" % (port_id))

    def get_ports(self, context, filters=None, fields=None):
        """
        Retrieves all port identifiers belonging to the
        specified Virtual Network.
        """
        port_dicts = self._list_resource('port', context, filters, fields)

        LOG.debug(
            "get_ports(): filters: " + pformat(filters) + " data: "
            + pformat(port_dicts))
        return port_dicts

    def get_ports_count(self, context, filters=None):
        """
        Get the count of ports.
        """
        ports_count = self._count_resource('port', context, filters)

        LOG.debug("get_ports_count(): filters: " + pformat(filters) +
                  " data: " + str(ports_count['count']))
        return ports_count['count']

    def _make_router_dict(self, router, status_code=None, fields=None,
                          process_extensions=True):
        res = {'id': router['id'],
               'name': router['name'],
               'tenant_id': router['tenant_id'],
               'admin_state_up': router['admin_state_up'],
               'status': router['status'],
               'external_gateway_info': None,
               'gw_port_id': router['gw_port_id']}
        if router['gw_port_id']:
            nw_id = router['gw_port_id']['network_id']
            res['external_gateway_info'] = {'network_id': nw_id}
        # NOTE(salv-orlando): The following assumes this mixin is used in a
        # class inheriting from CommonDbMixin, which is true for all existing
        # plugins.
        if process_extensions:
            self._apply_dict_extend_functions(
                l3.ROUTERS, res, router)
        return self._fields(res, fields)

    # Router API handlers
    def create_router(self, context, router):
        """
        Creates a new Logical Router, and assigns it
        a symbolic name.
        """
        plugin_router = copy.deepcopy(router)

        router_dicts = self._create_resource('router', context, plugin_router)
        LOG.debug("create_router(): " + pformat(router_dicts) + "\n")

        return router_dicts

    def get_router(self, context, router_id, fields=None):
        """
        Get the attributes of a router
        """
        router_dicts = self._get_resource('router', context, router_id, fields)

        LOG.debug("get_router(): " + pformat(router_dicts))
        return router_dicts

    def update_router(self, context, router_id, router):
        """
        Updates the attributes of a router
        """
        plugin_router = copy.deepcopy(router)
        router_dicts = self._update_resource('router', context, router_id,
                                             plugin_router)

        LOG.debug("update_router(): " + pformat(router_dicts))
        return router_dicts

    def delete_router(self, context, router_id):
        """
        Deletes a router
        """
        self._delete_resource('router', context, router_id)

        LOG.debug("delete_router(): %s" % (router_id))

    def get_routers(self, context, filters=None, fields=None):
        """
        Retrieves all router identifiers
        """
        router_dicts = self._list_resource('router', context, filters, fields)

        LOG.debug(
            "get_routers(): filters: " + pformat(filters) + " data: "
            + pformat(router_dicts))
        return router_dicts

    def get_routers_count(self, context, filters=None):
        """
        Get the count of routers
        """
        routers_count = self._count_resource('router', context, filters)

        LOG.debug("get_routers_count(): filters: " + pformat(filters) +
                  " data: " + str(routers_count['count']))
        return routers_count['count']

    def add_router_interface(self, context, router_id, interface_info):
        if not interface_info:
            msg = _("Either subnet_id or port_id must be specified")
            raise exc.BadRequest(resource='router', msg=msg)

        try:
            cfgdb = NeutronPluginContrailCoreV2._get_user_cfgdb(context)
            if 'port_id' in interface_info:
                if 'subnet_id' in interface_info:
                    msg = _("Cannot specify both subnet-id and port-id")
                    raise exc.BadRequest(resource='router', msg=msg)

                port_id = interface_info['port_id']
                return cfgdb.add_router_interface(router_id, port_id=port_id)
            elif 'subnet_id' in interface_info:
                subnet_id = interface_info['subnet_id']
                return cfgdb.add_router_interface(router_id,
                                                  subnet_id=subnet_id)
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def remove_router_interface(self, context, router_id, interface_info):
        if not interface_info:
            msg = _("Either subnet_id or port_id must be specified")
            raise exc.BadRequest(resource='router', msg=msg)

        try:
            cfgdb = NeutronPluginContrailCoreV2._get_user_cfgdb(context)
            if 'port_id' in interface_info:
                port_id = interface_info['port_id']
                return cfgdb.remove_router_interface(router_id,
                                                     port_id=port_id)
            elif 'subnet_id' in interface_info:
                subnet_id = interface_info['subnet_id']
                return cfgdb.remove_router_interface(router_id,
                                                     subnet_id=subnet_id)
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    # Floating IP API handlers
    def _make_floatingip_dict(self, floatingip, status_code=None, fields=None):
        res = {'id': floatingip['id'],
               'tenant_id': floatingip['tenant_id'],
               'floating_ip_address': floatingip['floating_ip_address'],
               'floating_network_id': floatingip['floating_network_id'],
               'router_id': floatingip['router_id'],
               'port_id': floatingip['port_id'],
               'fixed_ip_address': floatingip['fixed_ip_address']}
        return self._fields(res, fields)

    def create_floatingip(self, context, floatingip):
        """
        Creates a floating IP.
        """
        plugin_fip = copy.deepcopy(floatingip)

        fip_dicts = self._create_resource('floatingip', context, plugin_fip)
        LOG.debug("create_floatingip(): " + pformat(fip_dicts) + "\n")

        return fip_dicts

    def update_floatingip(self, context, fip_id, floatingip):
        """
        Updates the attributes of a floating IP
        """
        plugin_fip = copy.deepcopy(floatingip)
        fip_dicts = self._update_resource('floatingip', context, fip_id,
                                          plugin_fip)

        LOG.debug("update_floatingip(): " + pformat(fip_dicts))
        return fip_dicts

    def get_floatingip(self, context, fip_id, fields=None):
        """
        Get the attributes of a floating ip.
        """
        fip_dicts = self._get_resource('floatingip', context, fip_id, fields)

        LOG.debug("get_floatingip(): " + pformat(fip_dicts))
        return fip_dicts

    def delete_floatingip(self, context, fip_id):
        """
        Deletes a floating IP
        """
        self._delete_resource('floatingip', context, fip_id)

        LOG.debug("delete_floatingip(): %s" % (fip_id))

    def get_floatingips(self, context, filters=None, fields=None):
        """
        Retrieves all floating ips identifiers
        """
        fip_dicts = self._list_resource('floatingip', context, filters, fields)

        LOG.debug(
            "get_floatingips(): filters: " + pformat(filters) + " data: "
            + pformat(fip_dicts))
        return fip_dicts

    def get_floatingips_count(self, context, filters=None):
        """
        Get the count of floating IPs.
        """
        fips_count = self._count_resource('floatingip', context, filters)

        LOG.debug("get_floatingips_count(): filters: " + pformat(filters) +
                  " data: " + str(fips_count['count']))
        return fips_count['count']

    def plug_interface(self, tenant_id, net_id, port_id, remote_interface_id):
        """
        Attaches a remote interface to the specified port on the
        specified Virtual Network.
        """
        port = self._get_port(tenant_id, net_id, port_id)
        # Validate attachment
        self._validate_attachment(tenant_id, net_id, port_id,
                                  remote_interface_id)
        if port['interface_id']:
            raise exc.PortInUse(net_id=net_id, port_id=port_id,
                                att_id=port['interface_id'])
        db.port_set_attachment(port_id, net_id, remote_interface_id)

    def unplug_interface(self, tenant_id, net_id, port_id):
        """
        Detaches a remote interface from the specified port on the
        specified Virtual Network.
        """
        self._get_port(tenant_id, net_id, port_id)
        db.port_unset_attachment(port_id, net_id)

    # VPC route table handlers
    def _make_route_table_routes_dict(self, route_table_route, fields=None):
        res = {'prefix': route_table_route['prefix'],
               'next_hop': route_table_route['next_hop']}

        return self._fields(res, fields)

    def _make_route_table_dict(self, route_table, fields=None):
        res = {'id': route_table['id'],
               'name': route_table['name'],
               'fq_name': route_table['fq_name'],
               'tenant_id': route_table['tenant_id']}
        if route_table['routes']:
            res['routes'] = [self._make_route_table_routes_dict(r)
                             for r in route_table['routes']['route']]
        else:
            res['routes'] = {}
        return self._fields(res, fields)

    def create_route_table(self, context, route_table):
        try:
            cfgdb = NeutronPluginContrailCoreV2._get_user_cfgdb(context)
            rt_info = cfgdb.route_table_create(
                          route_table['route_table'])

            # verify transformation is conforming to api
            rt_dict = self._make_route_table_dict(rt_info['q_api_data'])
            rt_dict.update(rt_info['q_extra_data'])
            LOG.debug("create_route_table(): " + pformat(rt_dict))
            return rt_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def update_route_table(self, context, id, route_table):
        """
        Updates the attributes of a particular route table.
        """
        try:
            cfgdb = NeutronPluginContrailCoreV2._get_user_cfgdb(context)
            rt_info = cfgdb.route_table_update(id, route_table['route_table'])

            rt_dict = self._make_route_table_dict(rt_info['q_api_data'])
            rt_dict.update(rt_info['q_extra_data'])
            LOG.debug("create_route_table(): " + pformat(rt_dict))
            return rt_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def delete_route_table(self, context, id):
        try:
            cfgdb = NeutronPluginContrailCoreV2._get_user_cfgdb(context)
            cfgdb.route_table_delete(id)
            LOG.debug("delete_route_table(): " + pformat(id))
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def get_route_tables(self, context, filters=None, fields=None,
                         sorts=None, limit=None, marker=None,
                         page_reverse=False):
        try:
            cfgdb = NeutronPluginContrailCoreV2._get_user_cfgdb(context)
            route_tables_info = cfgdb.route_table_list(context, filters)

            route_tables_dicts = []
            for rt_info in route_tables_info:
                # verify transformation is conforming to api
                rt_dict = self._make_route_table_dict(rt_info['q_api_data'],
                                                      fields)

                rt_dict.update(rt_info['q_extra_data'])
                route_tables_dicts.append(rt_dict)

            LOG.debug(
                "get_route_tables(): filter: " + pformat(filters)
                + 'data: ' + pformat(route_tables_dicts))
            return route_tables_dicts
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def get_route_table(self, context, id, fields=None):
        try:
            cfgdb = NeutronPluginContrailCoreV2._get_user_cfgdb(context)
            rt_info = cfgdb.route_table_read(id)

            # verify transformation is conforming to api
            rt_dict = self._make_route_table_dict(rt_info['q_api_data'],
                                                  fields)

            rt_dict.update(rt_info['q_extra_data'])

            LOG.debug("get_route_table(): " + pformat(rt_dict))
            return self._fields(rt_dict, fields)
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    # VPC route table svc instance handlers
    def _make_svc_instance_dict(self, svc_instance, fields=None):
        res = {'id': svc_instance['id'],
               'name': svc_instance['name'],
               'tenant_id': svc_instance['tenant_id']}
        if svc_instance['internal_net']:
            res['internal_net'] = svc_instance['internal_net']
        if svc_instance['external_net']:
            res['external_net'] = svc_instance['external_net']
        return self._fields(res, fields)

    def create_nat_instance(self, context, nat_instance):
        try:
            cfgdb = NeutronPluginContrailCoreV2._get_user_cfgdb(context)
            si_info = cfgdb.svc_instance_create(
                          nat_instance['nat_instance'])

            # verify transformation is conforming to api
            si_dict = self._make_svc_instance_dict(si_info['q_api_data'])

            si_dict.update(si_info['q_extra_data'])

            LOG.debug("create_nat_instance(): " + pformat(si_dict))
            return si_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def delete_nat_instance(self, context, id):
        try:
            cfgdb = NeutronPluginContrailCoreV2._get_user_cfgdb(context)
            cfgdb.svc_instance_delete(id)
            LOG.debug("delete_nat_instance(): " + pformat(id))
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def get_nat_instances(self, context, filters=None, fields=None,
                          sorts=None, limit=None, marker=None,
                          page_reverse=False):
        try:
            cfgdb = NeutronPluginContrailCoreV2._get_user_cfgdb(context)
            svc_instances_info = cfgdb.svc_instance_list(context, filters)

            svc_instances_dicts = []
            for si_info in svc_instances_info:
                # verify transformation is conforming to api
                si_dict = self._make_svc_instance_dict(si_info['q_api_data'],
                                                       fields)

                si_dict.update(si_info['q_extra_data'])
                svc_instances_dicts.append(si_dict)

            LOG.debug(
                "get_nat_instances(): filter: " + pformat(filters)
                + 'data: ' + pformat(svc_instances_dicts))
            return svc_instances_dicts
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def get_nat_instance(self, context, id, fields=None):
        try:
            cfgdb = NeutronPluginContrailCoreV2._get_user_cfgdb(context)
            si_info = cfgdb.svc_instance_read(id)

            # verify transformation is conforming to api
            si_dict = self._make_svc_instance_dict(si_info['q_api_data'],
                                                   fields)

            si_dict.update(si_info['q_extra_data'])

            LOG.debug("get_nat_instance(): " + pformat(si_dict))
            return self._fields(si_dict, fields)
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    # Security Group handlers
    def _make_security_group_rule_dict(self, security_group_rule, status_code=None, fields=None):
        if status_code != 200:
            if security_group_rule['type'] == 'BadRequest':
                raise exc.BadRequest(resource='security-group-rule', msg=security_group_rule['msg'])
            if security_group_rule['type'] == 'Conflict':
                raise exc.Conflict(resource='security-group-rule', msg=security_group_rule['msg'])
            if security_group_rule['type'] == 'NotFound':
                raise exc.NotFound(resource='security-group-rule', msg=security_group_rule['msg'])
        res = {'id': security_group_rule['id'],
               'tenant_id': security_group_rule['tenant_id'],
               'security_group_id': security_group_rule['security_group_id'],
               'ethertype': security_group_rule['ethertype'],
               'direction': security_group_rule['direction'],
               'protocol': security_group_rule['protocol'],
               'port_range_min': security_group_rule['port_range_min'],
               'port_range_max': security_group_rule['port_range_max'],
               'remote_ip_prefix': security_group_rule['remote_ip_prefix'],
               'remote_group_id': security_group_rule['remote_group_id']}

        return self._fields(res, fields)

    def _make_security_group_dict(self, security_group, status_code=None, fields=None):
        res = {'id': security_group['id'],
               'name': security_group['name'],
               'tenant_id': security_group['tenant_id'],
               'description': security_group.get('description')}
        res['security_group_rules'] = [self._make_security_group_rule_dict(status_code, r)
                                       for r in security_group.get('rules', [])]
        return self._fields(res, fields)

    def create_security_group(self, context, security_group):
        """
        Creates a Security Group.
        """
        plugin_sg = copy.deepcopy(security_group)

        sg_dicts = self._create_resource('security_group', context, plugin_sg)
        LOG.debug("create_security_group(): " + pformat(sg_dicts) + "\n")

        return sg_dicts

    def get_security_group(self, context, sg_id, fields=None):
        """
        Get the attributes of a security group.
        """
        sg_dicts = self._get_resource('security_group', context, sg_id, fields)

        LOG.debug("get_security_group(): " + pformat(sg_dicts))
        return sg_dicts

    def update_security_group(self, context, sg_id, security_group):
        """
        Updates the attributes of a security group
        """
        plugin_sg = copy.deepcopy(security_group)
        sg_dicts = self._update_resource('security_group', context, sg_id,
                                          plugin_sg)

        LOG.debug("update_security_group(): " + pformat(sg_dicts))
        return sg_dicts

    def delete_security_group(self, context, sg_id):
        """
        Deletes a security group
        """
        status, value = self._delete_resource('security_group', context, sg_id)
        if status != 200:
            if value['type'] == 'SecurityGroupCannotRemoveDefault':
                raise securitygroup.SecurityGroupCannotRemoveDefault()
            if value['type'] == 'SecurityGroupInUse':
                raise securitygroup.SecurityGroupInUse(id=sg_id)
        LOG.debug("delete_security_group(): %s" % (sg_id))

    def get_security_groups(self, context, filters=None, fields=None,
                            sorts=None, limit=None, marker=None,
                            page_reverse=False):
        """
        Retrieves all security group identifiers
        """
        sg_dicts = self._list_resource('security_group', context,
                                       filters, fields)

        LOG.debug(
            "get_security_groups(): filters: " + pformat(filters) + " data: "
            + pformat(sg_dicts))
        return sg_dicts

    def create_security_group_rule(self, context, security_group_rule):
        """
        Creates a security group rule
        """
        plugin_sg_rule = copy.deepcopy(security_group_rule)

        sg_rule_dicts = self._create_resource('security_group_rule', context,
                                              plugin_sg_rule)
        LOG.debug("create_security_group_rule(): " + 
                  pformat(sg_rule_dicts) + "\n")

        return sg_rule_dicts

    def delete_security_group_rule(self, context, sg_rule_id):
        """
        Deletes a security group rule
        """
        self._delete_resource('security_group_rule', context, sg_rule_id)

        LOG.debug("delete_security_group_rule(): %s" % (sg_rule_id))

    def get_security_group_rule(self, context, sg_rule_id, fields=None):
        """
        Get the attributes of a security group rule
        """
        sg_rule_dicts = self._get_resource('security_group_rule', context,
                                           sg_rule_id, fields)

        LOG.debug("get_security_group_rule(): " + pformat(sg_rule_dicts))
        return sg_rule_dicts

    def get_security_group_rules(self, context, filters=None, fields=None,
                                 sorts=None, limit=None, marker=None,
                                 page_reverse=False):
        """
        Retrieves all security group rules
        """
        sg_rule_dicts = self._list_resource('security_group_rule', context,
                                            filters, fields)

        LOG.debug(
            "get_security_group_rules(): filters: " + pformat(filters)
            + " data: " + pformat(sg_rule_dicts))
        return sg_rule_dicts
