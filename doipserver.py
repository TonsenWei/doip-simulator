"""
   Copyright 2019 Rohan Fletcher 

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""

from lib.discover import DOIPDiscoverThread
from lib.server import DOIPServer

import time

from lib import utils
from lib.simulator import fstep, framp, fsine, IdentifierDataSimulator

import logging
# logging.basicConfig(level=logging.WARNING)
logging.basicConfig(level=logging.INFO)


def accelerator_format(n):
    return [n]

def brakehydralic_format(n):
    return utils.num_to_bytes(n, 2)

def steeringangle_format(n):
    sign = 1 if n < 0 else 0
    magnitude = abs(n)
    return utils.num_to_bytes(magnitude, 2) + [sign]


config = {
    'vin': 'TESTVIN0000012345',
    'mac': int('123456789ABC', 16),
    'addresses': {
        'discovery': 0x3000,
        'server': 0x3010,
    },
    'datamap': {
        0x3300: {
            0x3200: ('Dummy Accelerator', framp(0xff, 2, 0), accelerator_format),
            0x3230: ('Dummy Brake', framp(0x5000, 10, 0), brakehydralic_format),
        },
        0x3000: {
            0x3200: ('Dummy Accelerator', framp(0xff, 2, 0), accelerator_format),
            0x3230: ('Dummy Brake', framp(0x5000, 10, 0), brakehydralic_format),
        },
        0x3301: {
            0x3250: ('Dummy Steering', fsine(0x7fff, 4, 0), steeringangle_format),
        }
    }
}



def main():
    simulator = IdentifierDataSimulator(config['datamap'])

    discovery_thread = DOIPDiscoverThread(config)
    discovery_thread.start()

    server = DOIPServer(config, simulator)
    server.serve_forever()

if __name__ == '__main__':
    main()
