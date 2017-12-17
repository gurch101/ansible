#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2015, Patrick F. Marques <patrickfmarques@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: digital_ocean_floating_ip
short_description: Manage DigitalOcean Floating IPs
description:
     - Create/delete/assign a floating IP.
version_added: "2.4"
author: "Patrick Marques (@pmarques)"
options:
  state:
    description:
     - Indicate desired state of the target.
    default: present
    choices: ['present', 'absent']
  ip:
    description:
     - Public IP address of the Floating IP. Used to remove an IP
    required: false
    default: None
  region:
    description:
     - The region that the Floating IP is reserved to.
    required: false
    default: None
  droplet_id:
    description:
     - The Droplet that the Floating IP has been assigned to.
    required: false
    default: None
  oauth_token:
    description:
     - DigitalOcean OAuth token.
    required: true

notes:
  - Version 2 of DigitalOcean API is used.
requirements:
  - "python >= 2.6"
'''


EXAMPLES = '''
- name: "Create a Floating IP in region lon1"
  digital_ocean_floating_ip:
    state: present
    region: lon1

- name: "Create a Floating IP assigned to Droplet ID 123456"
  digital_ocean_floating_ip:
    state: present
    droplet_id: 123456

- name: "Delete a Floating IP with ip 1.2.3.4"
  digital_ocean_floating_ip:
    state: absent
    ip: "1.2.3.4"

'''


RETURN = '''
# Digital Ocean API info https://developers.digitalocean.com/documentation/v2/#floating-ips
data:
    description: a DigitalOcean Floating IP resource
    returned: success and no resource constraint
    type: dict
    sample: {
      "action": {
        "id": 68212728,
        "status": "in-progress",
        "type": "assign_ip",
        "started_at": "2015-10-15T17:45:44Z",
        "completed_at": null,
        "resource_id": 758603823,
        "resource_type": "floating_ip",
        "region": {
          "name": "New York 3",
          "slug": "nyc3",
          "sizes": [
            "512mb",
            "1gb",
            "2gb",
            "4gb",
            "8gb",
            "16gb",
            "32gb",
            "48gb",
            "64gb"
          ],
          "features": [
            "private_networking",
            "backups",
            "ipv6",
            "metadata"
          ],
          "available": true
        },
        "region_slug": "nyc3"
      }
    }
'''

import time

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback
from ansible.module_utils.digital_ocean import DigitalOceanHelper


class DOFloatingIP(object):
    def __init__(self, module):
        self.module = module
        self.rest = DigitalOceanHelper(module)

    def create(self):
        payload = {}
        if self.module.params['region'] is not None:
            payload["region"] = self.module.params['region']
        if self.module.params['droplet_id'] is not None:
            payload["droplet_id"] = self.module.params['droplet_id']

        response = self.rest.post("floating_ips", data=payload)
        status_code = response.status_code
        json_data = response.json
        if status_code == 202:
            self.module.exit_json(changed=True, data=json_data)
        else:
            self.module.fail_json(msg="Error creating floating ip [{0}: {1}]".format(
                status_code, json_data["message"]), region=self.module.params['region'])

    def delete(self):
        ip = self.module.params['ip']
        # TODO: test what happens for unassigned IP
        # self.unassign()
        response = self.rest.delete("floating_ips/{0}".format(ip))
        status_code = response.status_code
        json_data = response.json
        if status_code == 204:
            self.module.exit_json(changed=True)
        elif status_code == 404:
            self.module.exit_json(changed=False)
        else:
            self.module.exit_json(changed=False, data=json_data)

    def retrieve(self):
        ip = self.module.params['ip']
        response = self.rest.get("floating_ips/{0}".format(ip))
        status_code = response.status_code
        json_data = response.json
        if status_code == 200:
            return json_data['floating_ip']
        else:
            self.module.fail_json(msg="Error retrieving floating ip [{0}: {1}]".format(
                status_code, json_data["message"]))

    def do_action(self, payload):
        ip = self.module.params['ip']
        response = self.rest.post("floating_ips/{0}/actions".format(ip), data=payload)
        status_code = response.status_code
        json_data = response.json
        self.module.exit_json(msg='%s' % (status_code,))
        if status_code == 201:
            self.rest.poll_action_for_status(json_data['action']['id'], status='completed')
            self.module.exit_json(changed=True, data=json_data)
        else:
            self.module.fail_json(msg="Error completing floating ip action [{0}: {1}]".format(
                payload['type'], json_data["message"]))

    def assign_to_droplet(self):
        details = self.retrieve()
        droplet = details['droplet']
        if droplet is not None and str(droplet['id']) in [self.module.params['droplet_id']]:
            self.module.exit_json(changed=False)
        payload = {
            "type": "assign",
            "droplet_id": self.module.params['droplet_id']
        }
        self.do_action(payload)

    def unassign(self):
        payload = {
            "type": "unassign"
        }
        self.do_action(payload)


def core(module):
    floating_ip = DOFloatingIP(module)
    state = module.params['state']
    if state == 'present':
        if module.params['droplet_id'] is not None and module.params['ip'] is not None:
            floating_ip.assign_to_droplet()
        else:
            floating_ip.create()
    elif state == 'absent':
        floating_ip.delete()


def main():
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(choices=['present', 'absent'], default='present'),
            ip=dict(aliases=['id'], required=False),
            region=dict(required=False),
            droplet_id=dict(required=False),
            oauth_token=dict(
                no_log=True,
                # Support environment variable for DigitalOcean OAuth Token
                fallback=(env_fallback, ['DO_API_TOKEN', 'DO_API_KEY', 'DO_OAUTH_TOKEN']),
                required=True,
            ),
            validate_certs=dict(type='bool', default=True),
            timeout=dict(type='int', default=30),
        ),
        required_if=([
            ('state', 'delete', ['ip'])
        ]),
        mutually_exclusive=(
            ['region', 'droplet_id']
        ),
    )

    core(module)


if __name__ == '__main__':
    main()
