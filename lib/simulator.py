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

import math
import time

import logging
logger = logging.getLogger('simulator')


def fsine(A, p, c):
    # y = A * sin(2*pi*w*t) + c
    def func(t, t0):
        return int(A * math.sin(2.0 * math.pi / p * (t - t0)) + c)
    return func

def fstep(A, p, c):
    def func(t, t0):
        delta = (t - t0) / float(p)
        delta = delta - int(delta)
        print(delta)
        if delta > 0.5:
            dir = 0
        else:
            dir = 1
        return int(A * dir + c)
    return func

def framp(A, p, c):
    def func(t, t0):
        delta = (t - t0) / float(p)
        delta = delta - int(delta)
        return int(A * delta + c)
    return func

class TargetAddressNotFound(Exception):
    pass

class IdentifierNotFound(Exception):
    pass

class IdentifierDataSimulator(object):
    def __init__(self, identifier_map):
        self.identifier_map = identifier_map
        self.start_time = time.time()

    def has_target_address(self, target_address):
        return target_address in self.identifier_map

    def read_value(self, target_address, identifier):
        target_map = self.identifier_map.get(target_address)
        if target_map is None:
            raise IdentifierNotFound('Target address "0x{:04x}" not found'.format(target_address))
        endpoint = target_map.get(identifier)
        if endpoint is None:
            raise IdentifierNotFound('Identifier "0x{:04x}" not found for target address "0x{:04x}"'.format(identifier, target_address))
        label, generator_fn, format_fn = endpoint
        timestamp = time.time()
        logger.info('Generating value for {} (0x{:04x} on target 0x{:04x})'.format(label, identifier, target_address))
        value = generator_fn(timestamp, self.start_time)
        data = bytearray(format_fn(value))
        logger.info('{} value at time {} is {}'.format(label, timestamp, data))
        return data
