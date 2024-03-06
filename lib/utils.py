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

import inspect

def get_subclasses(mod, cls):
    """Yield the classes in module ``mod`` that inherit from ``cls``"""
    for name, obj in inspect.getmembers(mod):
        if hasattr(obj, "__bases__") and cls in obj.__bases__:
            yield obj

def num_to_bytes(num, numbytes):
    data = []

    for idx in range(numbytes):
        data.insert(0, num & 0xff)
        num >>= 8

    return data

def bytes_to_num(data):
    num = 0
    for d in data:
        num <<= 8
        num |= d
    return num

def bytes_to_hex(data):
    return " ".join([hex(d)[2:] for d in data])
