# aws_tag


An Ansible lookup plugin for based loosely around AWS tag lookups.


Supports:
    - ec2
    - security groups
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

And this returns all running instances with the 'Name' tag of mgmt-elasticsearch:

    - debug: msg="get ec2 instance details and register it to a variable"
      with_aws_tag:
        aws_resource: "ec2"
        aws_tag_key: "Name"
        aws_tag_value: "mgmt-elasticsearch"
        state: "running"  # running is actually the default, but others are supported!
	  register: resp

which will return a relatively large payload: [gist](https://gist.github.com/tfishersp/17ce75695c9f2e493416)