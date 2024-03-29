import json
import os
import sys
from ansible import utils, errors
from ansible.module_utils import ec2

# Licensed under the BSD 3-Clause License, see the LICENSE file for more details.
# tristan fisher (github.com/tfishersp; github.com/tristanfisher)

VERSION = '1.0'

# Dev notes:
# using an instance of basic.AnsibleModule as a "rolling parts car" for binding methods onto AWSResource
# is more trouble then it's worth because of the interdependent nature of the AnsibleModule object.
# - for consideration: a number of attributes come back as '\n                            ' consider stripping off.


# TODO:
# DRY up the 'if not filter dict' (maybe move this into the init so it's just there for access from methods?)
# Refactor, dry up, allow resource item chaining -- VPC(Filter)->RouteTable(resultSet of VPC(Filter))
# Look into how the attr access and object generation happens for vpc route.  i think that makes more sense

DOC = """An Ansible lookup plugin for returning AWS resources based on tags.

Supports:
    - ec2
    - subnets
    - vpc

Supports specifying tags by key/value specification:

    aws_tag_key: "Name"
    aws_tag_value: "mgmt"

or via a dictionary:

    aws_tag_dict: {"Environment": "mgmt", "Purpose": "logging"}

or via both:

    aws_tag_key: "Name"
    aws_tag_value: "mgmt"
    aws_tag_dict: {"Environment": "mgmt", "Purpose": "logging"}

    [results in {"Name": "mgmt", "Environment": "mgmt", "Purpose": "logging"} for the lookup filter.]

or via both with an override:

    aws_tag_dict: {"Environment": "mgmt", "Purpose": "logging"}
    aws_tag_key: "Environment"
    aws_tag_value: "prod"

    [results in {"Environment": "prod", "Purpose": "logging"} for the lookup filter as the dictionary approach
    has lower precedence.]

or, finally, using a simple lookup that defaults to a aws_tag_key of "Name":

    aws_tag_value: "mgmt_logging"

    [results in {"Name": "mgmt_logging"]


Note that you are *not* forced to prefix "tag:" on your keys as this plugin handles it for you.


Ansible task usage:

    with_aws_tag:
        aws_resource: "vpc"
        aws_tag_key: "Environment"
        aws_tag_value: "mgmt"
        aws_region: "us-east-1"

This returns all matching VPC objects (e.g. vpc-xxxxxxx) in the us-east-1 region:

    "item": {
        "cidr_block": "10.0.0.0/16",
        "classic_link_enabled": null,
        "dhcp_options_id": "dopt-aac591c2",
        "id": "vpc-9b9bcbfe",
        "instance_tenancy": "default",
        "is_default": false,
        "item": "\n        ",
        "region": {
            "endpoint": "",
            "name": ""
        },
        "state": "available",
        "tags": {
            "Environment": "mgmt",
            "Name": "mgmt"
        }
    }

"""

WORKAROUNDS="""

Issue: A variable inserted a new parameter into the module args. Be sure to quote variables...

Solution: Replace the '=' in the output with some harmless variable:

- name: Route tables - return route table
  debug: var="{{ item }}"
  with_aws_tag:
    aws_resource: "routetable"
    aws_filter_dict: {
      "vpc_id": "vpc-xxxxxxx"
    }
  register: myroutingtable


- debug: var="{{ item.item.id |replace("=", "QUACKQUACK") }}"
  with_items:
    - "{{ myroutingtable.results }}"


"""

# do all the imports and depedency injection in one shot.
try:
    import boto
    import boto.ec2
    import boto.vpc
    import boto.s3
    # dependency injection because ansible doesn't bind its requirements in the ec2 module
    ec2.os = os
    ec2.boto = boto
    ec2.boto.ec2 = boto.ec2
    ec2.boto.vpc = boto.vpc
    ec2.boto.s3 = boto.s3
except ImportError:
    raise errors.AnsibleError("failed=True msg='boto required for this module'")


vague_tag_msg = """
You must specify a string for an aws_tag_value.

Special cases:
* or %      : match all
'' or ""    : match all with no value

This command does not default to "match all" because of the potentially serious consequence of
misconceptions on behalf of the playbook or module author.
"""


class AWSResource(object):

    # -- Setup/Plumbing/Make defaults obvious --#
    def __init__(self, aws_resource=None, aws_tag_key=None, aws_tag_value=None, aws_region=None,
                 aws_tag_dict={}, state=None, debug=False, terms=[], **kwargs):

        # -- plain attrs -- #
        # ansible wants a list response.
        self._response = []

        # DWIM matching
        self.match_all_param = ['*', '%', 'all']
        self.match_all = False

        # keyed lookup for connection details and data return
        self.aws_conn = {}
        self.api_response = {}
        self.api_response['ec2'] = {}
        self.api_response['routetable'] = {}
        self.api_response['s3'] = {}
        self.api_response['sg'] = {}
        self.api_response['subnet'] = {}
        self.api_response['vpc'] = {}

        # -- property and iter+setattr attrs --#

        # to fit into the ansible style of lookup plugins, allow terms to come in as a list
        # TODO: this whole thing is a mess once we take into account
        # that we might want to allow for multiple filter lines
        if terms:
            _swap = {}

            # if terms were set as a plain dictionary (coming from jinja without a preceeding '-', we need to convert
            # the dict to a list or handle the for iteration differently.
            if isinstance(terms, dict):
                _l = []
                for k, v in terms.items():
                    _l.append({k: v})
                terms = _l

            # i hope you don't have duplicate keys :)
            for t in terms:
                _swap.update(t)

            # resist the urge to call the following (it skips properties): self.__dict__.update(_swap)
            # use setattrs to populate :
            any(setattr(self, key, value) for key, value in _swap.items())

            # i know, del use...but i don't want potential confusion to persist and we're done with the terms
            del _swap
            del terms

        # False from debug arg or what was populated via terms
        self.debug = debug
        # todo: implement debugging info for users that ask for it
        # if self.debug:

        # use properties to set defaults/handle None. (self._param should not be initialized to None)
        self.aws_resource = aws_resource
        self.aws_tag_key = aws_tag_key
        self.aws_tag_value = aws_tag_value
        self.aws_region = aws_region
        self.state = state

        # we give a certain amount of trust on this as the implementing-users will also be employees.
        # (there's nothing to keep a user from subverting dunders or being otherwise annoying)
        for k, v in kwargs.items():
            setattr(self, k, v)

        # Check on none -- tags can be 0 or falsey
        if self.aws_tag_value is None and self.aws_tag_dict is None and self.aws_filter_dict is None:
            raise errors.AnsibleError(vague_tag_msg)

        # it should be safe to downcase '%' or '*' in unicode.  see case mapping:
        #   ftp://ftp.unicode.org/Public/UCD/latest/ucd/UnicodeData.txt
        #
        # >>> u = unicode('*')
        # >>> ord(u), hex(ord(u)), unicodedata.category(u), unicodedata.name(u)
        # (42, '0x2a', 'Po', 'ASTERISK')
        #
        # there's no downcase equiv -- predict return of self or an error from libraries
        # TODO: there's a default that sets name in absence of other tags.  name=[all,*, %] could make issues.
        # TODO: need to check for 'all'-like in aws_tag_dict too
        # check for all=all ?

        if self.aws_tag_value:
            if self.aws_tag_value.lower() in self.match_all_param:
                self.match_all = True

        # needed to fake out get_aws_connection_info in ec2.py
        # this will cause ec2.py to look at the os.environ series if the params aren't bound on this obj.
        self.params = {}
        self.params['region'] = self.aws_region
        # use ec2's param grabber for convenience (gets access/secret key, etc)
        self.aws_params = ec2.get_aws_connection_info(self)
        # and then rebind the tuple onto our lookup dict for convenience
        self.params['aws_secret_access_key'] = self.aws_params[2]['aws_secret_access_key']
        self.params['aws_access_key_id'] = self.aws_params[2]['aws_access_key_id']
        self.params['security_token'] = self.aws_params[2]['security_token']

        self.getter_table = {
            'ec2': self.ec2_get_instances,
            'routetable': self.vpc_get_routetables,
            's3': None,
            'subnet': self.subnet_get_subnets,
            'subnets': self.subnet_get_subnets,
            'sg': self.sg_get_sgs,
            'securitygroup': self.sg_get_sgs,
            'vpc': self.vpc_get_vpcs
        }

        self.generate_filter_table = {
            'tags': self.generate_tag_filter_from_attrs,
            'filters': self.generate_filter_from_attrs
        }
        self.filters = []

        # bind a connection for our purpose on self
        self.bind_conn(self.aws_resource)

        # Call the relevant 'get' command, which calls generate_tag_filter_from_attrs in the absence
        # of passed variables.  By default, the 'get' command is responsible for binding its 'unpacked'/ready-for-use
        # response onto its api_response dict (e.g. self.api_response['ec2']['unpacked']

        self.getter_table[self.aws_resource]()

        # append the api_response dictionary for our target resource, targeting the key
        # that has been 'unpacked'/handled for return
        # filtering done in get call as of now.
        #self.api_response[self.aws_resource]['filtered'] = self.filter(self.api_response[self.aws_resource]['unpacked'])

        self._response = self.api_response[self.aws_resource]['unpacked']

        #self._response = self.prepare_response(self.api_response[self.aws_resource]['unpacked'])

    # -- properties and member attributes -- #

    @property
    def debug(self):
        try:
            return self._debug
        except:
            return False

    @debug.setter
    def debug(self, _bool):
        self._debug = _bool

    # TODO: create property and setter for region, supporting default of 'all' which will return in every region.
    # could each region to a keyed lookup for aws_conn (e.g. self.aws_conn['us-east-1'] = ...
    @property
    def aws_region(self):
        try:
            return self._aws_region
        except AttributeError:
            return 'us-east-1'

    @aws_region.setter
    def aws_region(self, region):
        if region:
            self._aws_region = region
        if self.aws_region is None:
            self._aws_region = 'us-east-1'

    @property
    def aws_ec2_endpoint(self):
        try:
            return self._aws_ec2_endpoint
        except AttributeError:
            return 'us-east-1'

    @aws_ec2_endpoint.setter
    def aws_ec2_endpoint(self, ep):
        if ep:
            self._aws_ec2_endpoint = ep
        if self.aws_ec2_endpoint is None:
            self._aws_ec2_endpoint = 'ec2.%s.amazonaws.com' % self.aws_region

    @property
    def aws_resource(self):
        try:
            return self._aws_resource
        except AttributeError:
            return None

    @aws_resource.setter
    def aws_resource(self, resource):
        # construction of these allows term-list passing through setattr and handling of default param.
        # could maybe clean up, but low priority because the checks are dirt cheap
        if resource:
            self._aws_resource = resource
        if self.aws_resource is None:
            self._aws_resource = 'ec2'

    @property
    def aws_tag_key(self):
        try:
            return self._aws_tag_key
        except AttributeError: # we handle the default in the setter.
            return None

    @aws_tag_key.setter
    def aws_tag_key(self, key):
        if key:
            self._aws_tag_key = key
        if self.aws_tag_key is None:
            self._aws_tag_key = 'Name'

    @property
    def aws_tag_value(self):
        try:
            return self._aws_tag_value
        except AttributeError:
            return None

    @aws_tag_value.setter
    def aws_tag_value(self, val):
        if val:
            self._aws_tag_value = val

    @property
    def aws_filter_dict(self):
        try:
            return self._aws_filter_dict
        except AttributeError:
            return None

    @aws_filter_dict.setter
    def aws_filter_dict(self, val):
        if val:
            self._aws_filter_dict = val

    @property
    def aws_tag_dict(self):
        try:
            return self._aws_tag_dict
        except AttributeError:
            return None

    @aws_tag_dict.setter
    def aws_tag_dict(self, val):
        if val:
            self._aws_tag_dict = val

    @property
    def state(self):
        try:
            return self._state
        except AttributeError:
            return 'running'

    @state.setter
    def state(self, val):
        if val:
            self._state = val

    # -- member methods -- #

    # required for ansible integration
    # taken from module_utils/basic.py:AnsibleModule.jsonify() on 8-apr-2015
    def jsonify(self, data):
        for encoding in ("utf-8", "latin-1", "unicode_escape"):
            try:
                return json.dumps(data, encoding=encoding)
            # Old systems using simplejson module does not support encoding keyword.
            except TypeError, e:
                return json.dumps(data)
            except UnicodeDecodeError, e:
                continue
        self.fail_json(msg='Invalid unicode encoding encountered')

    # required for ansible integration
    # called on ec2.ec2_connect(self)
    def fail_json(self, **kwargs):
        # n.b. this is very little like AnsibleModule's fail_json
        assert 'msg' in kwargs, "implementation error -- msg to explain the error is required"
        kwargs['failed'] = True
        print self.jsonify(kwargs)
        sys.exit(1)

    # not required for ansible integration (and not in ansible itself)
    def warn(self, **kwargs):
        # return ansible-esque warnings when we hit an exception
        # that isn't _really_ fatal, but _is_ potentially bad.
        assert 'msg' in kwargs, "implementation error -- msg to explain the error is required"
        kwargs['warning'] = True

        # ANSI warning in red, error in purple (os.linesep because we've already included os)
        print(os.linesep + '\033[91mWARNING:\033[0m ' + '\033[95m' +kwargs['msg'] + '\033[0m' + os.linesep)

    def bind_conn(self, resource):
        if resource == 'ec2':
            # bind a connection to a region. we can query off of this object.  ec2 has an ansible connector
            self.aws_conn['ec2'] = ec2.ec2_connect(self)
        if resource == 'sg':
            self.aws_conn['sg'] = boto.ec2.connect_to_region(self.aws_region,
                                                             aws_access_key_id=self.params['aws_access_key_id'],
                                                             aws_secret_access_key=self.params['aws_secret_access_key'])
        if resource == 's3':
            self.aws_conn['s3'] = boto.connect_s3(aws_access_key_id=self.params['aws_access_key_id'],
                                                  aws_secret_access_key=self.params['aws_secret_access_key'])
        if resource == 'subnet':
            self.aws_conn['subnet'] = boto.connect_vpc(aws_access_key_id=self.params['aws_access_key_id'],
                                                       aws_secret_access_key=self.params['aws_secret_access_key'])

        if resource == 'routetable':
            self.aws_conn['routetable'] = boto.connect_vpc(aws_access_key_id=self.params['aws_access_key_id'],
                                                           aws_secret_access_key=self.params['aws_secret_access_key'])

        if resource == 'vpc':
            #might need to get region here by calling get_region(params['region'], **kwargs)
            self.aws_conn['vpc'] = boto.connect_vpc(aws_access_key_id=self.params['aws_access_key_id'],
                                                    aws_secret_access_key=self.params['aws_secret_access_key'])
        # give a default setting... only if we're not set to match_all (no point if *)



    # TODO: use of generate_filter_from_attrs will mean having to search filter _and_ filter_dict for attrs
    # with the merging of filter criteria before the get_all_RESOURCE(filter=filters_merged)

    def generate_filter_from_attrs(self):
        """ Handle filters that *are not* tags.

        """
        if self.aws_filter_dict:

            if "association.main" in self.aws_filter_dict:
                # https://github.com/boto/boto/issues/1742
                if self.aws_filter_dict["association.main"] is True:
                    self.aws_filter_dict["association.main"] = "true"

            return self.aws_filter_dict
            # not sure any transformation needs to happen
            # for k,v in self.filter_dict.items():


    def generate_tag_filter_from_attrs(self):

        # todo: implement AND-gate for
        # get name x or y:
        #   ...get_all_instances(filters={'tag:Name':['x', 'y']})

        _filter = {}

        # add the dict first
        # For items in the *tag_dict*, step into the entry and add 'tag:VALUE' if it's not already there,
        # as tags need to look like: {'tag:Name': 'mgmt2', 'tag:Environment': 'mgmt'}

        if self.aws_tag_dict:

            for k, v in self.aws_tag_dict.items():

                # TODO: move these to filter_dict when ready so we can deprecate the old style

                #todo: if you tag with vpc_id it will never be found. this may be a bad idea.
                # maybe preface unfiltered keywords with some string or take in a different arg for merging
                # e.g. aws_filters: {"vpc_id": "SOMETHING", "az": "SOMETHING ELSE"}

                # todo: this is another evil. pass user-convenience aliasing to a different function.
                if k.lower() in ['az', 'availabilityzone']:

                    # assign the key and make the item skip the tag pre-pend
                    new_k = 'availabilityZone'
                    self.aws_tag_dict[new_k] = v
                    self.aws_tag_dict.pop(k, None)
                    k = new_k

                # sin part 2, fix up the state for ec2-bound filters
                if k.lower() in ['state', 'instancestate', 'instance-state-name']:
                    new_k = 'instance-state-name'
                    self.aws_tag_dict[new_k] = v
                    self.aws_tag_dict.pop(k, None)
                    k = new_k

                if not k.startswith('tag:') and k != 'vpc_id' and k != 'availabilityZone' and k != 'state':
                    new_k = 'tag:%s' % k
                    self.aws_tag_dict[new_k] = v
                    self.aws_tag_dict.pop(k, None)

            try:
                _filter.update(self.aws_tag_dict)
            except Exception:
                self.fail_json(msg='generate_tag_filter_from_attrs failed with dict: %s' % self.aws_tag_dict)

        # and the specific items as higher precedent
        # _k defaults to Name
        _k = 'tag:%s' % self.aws_tag_key

        # _v does not. Do not assign a str(None)
        _v = '%s' % self.aws_tag_value if self.aws_tag_value else None

        # don't override Name if _v not set
        if _v is not None:
            _filter.update({_k: _v})

        return _filter

    def merge_filters(self, filters=[]):
        _ = {}
        for filt in filters:
            _.update(filt)
        return _

    def generate_filters(self, filters=['tags', 'filters']):
        """
        Generate the filters, implicitly from tag and filter dicts

        :param filters: name of defined dictionary lookup function (e.g. {'tags': generate_tag_filter_from_attrs})
        :return: flat list of dictionary filters [{}, {}]
        """
        _swap = []

        # if generation returns anything, append to _swap
        if 'tags' in filters:
            _ = self.generate_filter_table['tags']()
            if _:
                _swap.append(_)

        # generate_filter_from_attrs
        if 'filters' in filters:
            _ = _swap.append(self.generate_filter_table['filters']())
            if _:
                _swap.append(_)

        return self.merge_filters(_swap)


    def instance_unpack_block_device(self, obj):

        if obj:
            _d = {}
            _d[obj.current_name] = {
                "status": obj.current_value.status,
                "attach_time": obj.current_value.attach_time,
                "no_device": obj.current_value.no_device,
                "encrypted": obj.current_value.encrypted,
                "volume_id": obj.current_value.volume_id,
                "volume_type": obj.current_value.volume_type,
                "iops": obj.current_value.iops,
                "snapshot_id": obj.current_value.snapshot_id,
                "size": obj.current_value.size,
                "ebs": obj.current_value.ebs,
                "delete_on_termination": obj.current_value.delete_on_termination,
                "ephemeral_name": obj.current_value.ephemeral_name,
                "connection": str(obj.current_value.connection),
            }
        else:
            _d = None
        return _d

    def instance_unpack_interfaces(self, data):

        if data:
            _d = {}
            _d["is_truncated"] = data.is_truncated,
            _d["key_marker"] = data.key_marker,
            _d["marker"] = data.marker,
            _d["markers"] = str(data.markers),
            _d["networkInterfaceSet"] = data.networkInterfaceSet,
            _d["next_generation_marker"] = data.next_generation_marker,
            _d["next_key_marker"] = data.next_key_marker,
            _d["next_marker"] = data.next_marker,
            _d["next_token"] = data.next_token,
            _d["next_upload_id_marker"] = data.next_upload_id_marker,
            _d["next_version_id_marker"] = data.next_version_id_marker,
            _d["status"] = data.status,
            _d["version_id_marker"] = data.version_id_marker
        else:
            _d = None
        return _d

    def instance_jsonattrs(self, data):
        # return the useful attributes from the response object.  if we're missing something you depend on
        # please open a feature request

        # todo: review which of these should/can have a default None. making a guess
        _d = {}
        _d["handle"] = data.__str__()
        # TODO: ERROR HERE
        #       fatal: [localhost] => A variable inserted a new parameter into the module args.
        #       Be sure to quote variables if they contain equal signs (for example: "{{var}}").
        # TODO: when multi-block device, we need to [ device for device in getattr(data, 'block_device_mapping....
        _d["block_device_mapping"] = self.instance_unpack_block_device(getattr(data, 'block_device_mapping', None))
        _d["dns_name"] = getattr(data, 'dns_name', None)
        _d["ebs_optimized"] = getattr(data, 'ebs_optimized', None)
        _d["id"] = data.id
        _d["image_id"] = data.image_id
        _d["instance_type"] = data.instance_type

        # TODO: ERROR HERE
        #       fatal: [localhost] => A variable inserted a new parameter into the module args.
        #       Be sure to quote variables if they contain equal signs (for example: "{{var}}").
        _d["interfaces"] = self.instance_unpack_interfaces(data.interfaces)
        _d["ip_address"] = getattr(data, 'ip_address', None)
        _d["key_name"] = data.key_name
        _d["launch_time"] = data.launch_time
        _d["persistent"] = str(data.persistent)
        _d["private_dns_name"] = getattr(data, "private_dns_name", None)
        _d["private_ip_address"] = data.private_ip_address
        _d["public_dns_name"] = getattr(data, "public_dns_name", None)
        _d["region"] = dict(region=getattr(data.region, "name", ""), endpoint=getattr(data.region, "endpoint", ""))
        _d["root_device_name"] = data.root_device_name
        _d["root_device_type"] = data.root_device_type
        _d["subnet_id"] = getattr(data, "subnet_id", None)
        _d["tags"] = getattr(data, "tags", {})
        _d["virtualization_type"] = data.virtualization_type
        _d["vpc_id"] = getattr(data, "vpc_id", None)

        try:
            json.loads(json.dumps(_d))
        except ValueError:
            #
            self.warn("JSON object unable to encode for %s." % _d['handle'])
            self.fail_json(msg="ValueError: Invalid JSON from EC2 object.")

        return _d

    def ec2_unpack(self, data):
        # iter and unpack all we know from the inside of each instance obj
        instance_list = [instance_list.__dict__ for instance_list in data]

        for instance in instance_list:
            instance.pop('connection', None)

            try:
                # translate the obj to its useful elements, with empty string if getattr fails
                _r = {'name': getattr(instance['region'], 'name', ''), 'endpoint': getattr(instance['region'], 'endpoint', '')}
                instance['region'] = _r

                # groups - http://docs.aws.amazon.com/IAM/latest/APIReference/API_ListRoles.html
                instance['groups'] = dict((group.id, group.name) for group in instance['groups'])

                # Store the processed 'instance objects' (e.g.[Instance:i-4b116bb6])
                # in a list to reassign to the instance.
                in_l = []

                # result set is a list. i think this is more idiomatic than ...jsonattrs(instance['instances'][0])
                for in_iter in instance['instances']:
                    # todo: wrap with try/except in case only one response is bad?
                    try:
                        in_l.append(self.instance_jsonattrs(in_iter))
                    except TypeError:
                        self.warn(msg="%s returned with attributes that we could not properly handle.  "
                                      "Open a bug report, please." % (in_iter.__str__()))

                instance['instances'] = in_l

                # fatal: [localhost] => A variable inserted a new parameter into the module args.
                # number of args is the same -- we're swapping out <class 'boto.resultset.ResultSet'> for <type 'list'>
                # https://github.com/ansible/ansible/blob/fb96173d10dc7e3ae21fb4ab608859c426e6f548/lib/ansible/runner/__init__.py#L995-L998

                self.warn(msg='This currently fails if you request results. '
                              'Try deep access of an attribute beyond resp.results.[n]')

            except TypeError:
                self.warn(msg='TypeError when trying to unpack ec2 data.')
                self.fail_json(msg="Failed to parse response from Amazon.  This may be a bug.")

        return instance_list

    def ec2_get_instances(self, filter_dict={}, bind=True):

        if not filter_dict and not self.match_all:
            filter_dict = self.generate_tag_filter_from_attrs()

        if self.state:
            try:
                filter_dict.update({'instance-state-name': self.state})
            except Exception, e:
                self.fail_json(msg="Failed to update 'ec2_get_instances' with the self.state variable... %s" % e)

        if not self.match_all:
            i = self.aws_conn['ec2'].get_all_instances(filters=filter_dict)
        else:
            i = self.aws_conn['ec2'].get_all_instances()

        if bind:
            # list(result) to get the reservation ids instead of the class repr
            self.api_response['ec2']['list'] = list(i)
            self.api_response['ec2']['unpacked'] = self.ec2_unpack(i)

        else:
            return i

    def sg_jsonattrs(self, data):
        _d = {}
        _d['handle'] = data.__str__()
        _d['ip_protocol'] = data.ip_protocol
        _d['from_port'] = data.from_port
        _d['to_port'] = data.to_port
        _d['grants'] = [str(dg) for dg in data.grants]
        _d['ip_ranges'] = data.ipRanges
        return _d

    def sg_unpack(self, data):

        sg_list = [ sg_list.__dict__ for sg_list in data]

        for sg in sg_list:
            sg.pop('connection', None)

            try:
                _r = {'name': getattr(sg['region'], 'name', ''), 'endpoint': getattr(sg['region'], 'endpoint', '')}

                sg['region'] = _r

                sg_r_l = []
                for sg_r in sg['rules']:
                    sg_r_l.append(self.sg_jsonattrs(sg_r))

                sg_re_l = []
                for sg_re in sg['rules_egress']:
                    sg_re_l.append(self.sg_jsonattrs(sg_re))

                sg['rules'] = sg_r_l
                sg['rules_egress'] = sg_re_l

            except TypeError:
                sg['region'] = {'name': '', 'endpoint': ''}
                sg['rules'] = ['ERROR']
                sg['rules_egress'] = ['ERROR']

        return sg_list

    def sg_get_sgs(self, filter_dict={}, bind=True):
        if not filter_dict and not self.match_all:
            filter_dict = self.generate_tag_filter_from_attrs()

        if not self.match_all:
            # using groupName requires knowing the id...
            i = self.aws_conn['sg'].get_all_security_groups(filters=filter_dict)
        else:
            i = self.aws_conn['sg'].get_all_security_groups()
        if bind:
            self.api_response['sg']['list'] = i
            self.api_response['sg']['unpacked'] = self.sg_unpack(i)


    def subnet_get_subnets(self, filter_dict={}, bind=True):

        if not filter_dict and not self.match_all:
            filter_dict = self.generate_tag_filter_from_attrs()

        if not self.match_all:
            i = self.aws_conn['subnet'].get_all_subnets(filters=filter_dict)
        else:
            i = self.aws_conn['subnet'].get_all_subnets()

        if bind:
            self.api_response['subnet']['list'] = i
            # subnet unpacking can be currently done by vpc_unpack
            self.api_response['subnet']['unpacked'] = self.vpc_unpack(i)
        else:
            return i

    def vpc_route_unpack(self, data):
        """
        process data from get_all_route_tables() -- potentially already filtered by tags or vpc ids
        :param data: incoming [RouteTable:rtb-df5a61ba, RouteTable:rtb-16282573] objects
        :return: processed data dictionaries in lists
        """

        _data = []

        for route in data:

            _swap = {}

            try:

                _swap['region'] = dict(region=getattr(route.region, "name", ""),
                                       endpoint=getattr(route.region, "endpoint", ""))
                _swap['id'] = route.id
                #'item': u'\n        ',
                #no _swap['item']
                _swap['propagatingVgwSet'] = getattr(route, 'propagatingVgwSet', None)
                _swap['routes'] = [ str(r) for r in getattr(route, 'routes', []) ]
                _swap['tags'] = getattr(route, 'tags', {})
                _swap['vpc_id'] = getattr(route, 'vpc_id', '')

                ra_swap = getattr(data[0], 'associations', [])
                if ra_swap:
                    # I can't see anything I need in here as an actual item
                    ra_swap = ''[str(ra_swap.__dict__)]

                _swap['associations'] = ra_swap

            except TypeError:
                _swap['failed'] = 'True'

            _data.append(_swap)

        return _data

    def vpc_get_routetables(self, filter_dict={}, bind=True):

        # TODO: test out this new usage of the filter generation process

        # give a default setting... only if we're not set to match_all (no point if *)
        if not filter_dict and not self.match_all:
            filter_dict = self.generate_filters()

        if not self.match_all:
            # todo: refactor aws_conn style so we can do chaining of filters
            # (e.g. filter_vpc: dict/terms; filter_routetables: dict/terms; order: vpc->routetables
            #i = self.aws_conn['vpc'].get_all_vpcs(filters=filter_dict)
            # http://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeRouteTables.html
            i = self.aws_conn['routetable'].get_all_route_tables(filters=filter_dict)
        else:
            i = self.aws_conn['routetable'].get_all_route_tables()

        if bind:
            self.api_response['routetable']['list'] = i
            self.api_response['routetable']['unpacked'] = self.vpc_route_unpack(i)
        else:
            return i

    # filters applicable are here http://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVpcs.html
    def vpc_get_vpcs(self, filter_dict={}, bind=True):

        # give a default setting... only if we're not set to match_all (no point if *)
        if not filter_dict and not self.match_all:
            filter_dict = self.generate_tag_filter_from_attrs()

        if not self.match_all:
            i = self.aws_conn['vpc'].get_all_vpcs(filters=filter_dict)
        else:
            i = self.aws_conn['vpc'].get_all_vpcs()

        if bind:
            self.api_response['vpc']['list'] = i
            self.api_response['vpc']['unpacked'] = self.vpc_unpack(i)
        else:
            return i

    def vpc_unpack(self, data):
        vpc_list = [vpc_list.__dict__ for vpc_list in data]

        for _vpc_dict in vpc_list:
            _vpc_dict.pop('connection', None)
            # use collections's defaultdict if we end up doing this for other object types

            # handle the objects that come back from the response as they're not json serializable
            try:

                _r = {'name': getattr(_vpc_dict['region'], 'name', ''), 'endpoint': getattr(_vpc_dict['region'], 'endpoint', '')}

                _vpc_dict['region'] = _r

            except TypeError:
                # we asked for a non existent attrib on the key we might have just tried to create implicitly
                _vpc_dict['region'] = {
                    'name': '',
                    'endpoint': ''
                }

        return vpc_list

    # commented out to improve flow until this is field-tested
    # def prepare_response(self, data):
    #     # if this fires off, likely candidate is an object binding in data[iteration_n].values()
    #     if self.debug:
    #         try:
    #             # if this fails, ansible will fail later, with worse debugging output
    #             json.dumps(data)
    #         except TypeError, e:
    #             print("Reeived non-JSON serializable response from EC2.", ' => ', e)
    #
    #     return self._response.append(data)

    def filter(self, data):
        """Use this filter to provide filtering beyond that which AWS will do on its API"""

        _m = 'Pass filtering criteria to {resource}_get_* calls instead'
        self.fail_json(msg=_m)
        raise NotImplementedError(_m)

    def response(self):
        return self._response

    # -- introspection methods -- #

    def __str__(self):
        return str("<class {0.__class__.__name__}: aws_resource='{0.aws_resource}', "
                   "aws_tag_key='{0.aws_tag_key}', aws_tag_value='{0.aws_tag_value}'>".format(self))

    def __repr__(self):
        return str("<class {0}: __dict__ = {1} >".format(self.__class__.__name__, self.__dict__))


class LookupModule(object):

    def __init__(self, basedir=None, **kwargs):
        self.basedir = basedir

    def run(self, terms, inject=None, **kwargs):
        # turns inbound "thing" into a list (not specifically needed if we're passing in strings)
        terms = utils.listify_lookup_plugin_terms(terms, self.basedir, inject)

        if isinstance(terms, basestring):
            terms = [terms]

        resource = AWSResource(terms=terms)

        return resource.response()

if __name__ == '__main__':

    r = AWSResource(aws_tag_value='all')
    print(r)
    print(repr(r))