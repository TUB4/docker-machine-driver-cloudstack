# CloudStack driver for Docker Machine

## Status
_*** WORK IN PROGRESS ***_

This package is incomplete. At present, service-related parameters (zone, template, service offering) must be passed as CloudStack UUIDs. It can be used to create, control and destroy docker machines.

### To do:

- [ ] Map zone, template & service offering IDs to names.
- [ ] Update checkConfig( ) for the latter.
- [x] Add Destroy( ) function.
- [x] Add Start( ) function.
- [x] Add Restart( ) function.
- [x] Add Kill( ) function.
- [x] Add Stop( ) function.

### Known issues

If there is no default network present then CloudStack will create one. This can mean waiting for the system virtual router to spin up. This can sometimes cause docker-machine to time out.

**Solution:** Create a virtual network manually or use a persistent network.

## Create a machine

```
$ docker-machine create -d cloudstack <vm name>
Running pre-create checks...
Creating machine...
Waiting for machine to be running, this may take a few minutes...
Detecting operating system of created instance...
Waiting for SSH to be available...
Detecting operating system of created instance...
Provisioning created instance...
Copying certs to the local machine directory...
Copying certs to the remote machine...
Setting Docker configuration on the remote daemon...
To see how to connect Docker to this machine, run: docker-machine env example
```

Options:

| Option                      | Environment Variable      | Description                           |Required |
|-----------------------------|:-------------------------:|---------------------------------------|--------:|
| --cloudstack-endpoint          | CLOUDSTACK_ENDPOINT          | CloudStack API endpoint               | N |
| --cloudstack-api-key           | CLOUDSTACK_API_KEY           | CloudStack API key                    | Y |
| --cloudstack-secret-key        | CLOUDSTACK_SECRET_KEY        | CloudStack secret key                 | Y |
| --cloudstack-ssl               | CLOUDSTACK_SSL               | Verify SSL                            | N |
| --cloudstack-zone              | CLOUDSTACK_ZONE              | CloudStack  availability zone         | Y |
| --cloudstack-template          | CLOUDSTACK_TEMPLATE          | CloudStack  template                  | Y |
| --cloudstack-service-offering  | CLOUDSTACK_SERVICE_OFFERING  | CloudStack  service offering          | Y |

##Acknowledgements
This package uses the excellent [go-cloudstack] (https://github.com/xanzy/go-cloudstack) API client by Sander van Harmelen (<sander@xanzy.io>)

## Author
Christian Lafferty, BT Research & Innovation.

##License
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at <http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

Copyright (c) 2016 BT Group plc
