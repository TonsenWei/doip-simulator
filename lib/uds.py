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
import logging

from . import utils

class UDSException(Exception):
    pass

class InvalidMessage(UDSException):
    pass

class ServiceIDNotSupported(UDSException):
    pass


REGISTERED_SERVICEIDS = {}
def register_uds_message(cls):
    REGISTERED_SERVICEIDS[cls.service_id] = cls
    return cls

class UDSService(object):
    service_id = None

    def __init__(self, is_reply):
        self.is_reply = is_reply
        self.params = {}
        self.paramprint = {}

    @classmethod
    def parse(cls, data):
        if len(data) == 0:
            raise InvalidMessage('UDS message has 0 length')
        service_id = data[0] & 0xbf  # Get service ID
        is_reply = data[0] & 0x40 != 0
        if service_id not in REGISTERED_SERVICEIDS:
            raise ServiceIDNotSupported('Service id "{:02x} not supported"'.format(service_id))

        return REGISTERED_SERVICEIDS[service_id].parse(data[1:], is_reply=is_reply)

    def render(self, data, is_reply=False):
        service_id = self.service_id
        if is_reply:
            service_id |= 0x40

        if self.service_id is None:
            raise Exception('UDSMessage subclass has no service_id value')
        if service_id == 0x50:
            logging.info(f"render DiagnosticSession")
            return bytearray([service_id]) + data + b'\x00\x32\x13\x88'  # \x50\x02\x00\x32(P2)\x13\x88(P2_stat)
        else:
            logging.info(f"service_id not 0x10: {service_id = }")  # 80
            return bytearray([service_id]) + data

    def __str__(self):
        result = '{} [0x{:02x}, is_reply={}]:'.format(self.__class__.__name__, self.service_id, self.is_reply)
        if len(self.params) == 0:
            result += '<no params>'
        else:
            lines = []
            max_param_length = max([len(param) for param in self.params])
            for param, value in self.params.items():
                wrangler = self.paramprint.get(param)
                if wrangler:
                    value = wrangler(value)
                lines += ['    {:>{length}} = {}'.format(param, value, length=max_param_length)]
            result += "\n" + "\n".join(lines)
        return result

@register_uds_message
class TesterPresent(UDSService):
    service_id = 0x3e

    def __init__(self, suppress_reply=0x0, is_reply=False):
        super().__init__(is_reply)
        self.params['suppress_reply'] = suppress_reply
        self.paramprint['suppress_reply'] = lambda value: '0x{:02x}'.format(value)

    @classmethod
    def parse(cls, data, is_reply=False):
        if len(data) < 1:
            raise InvalidMessage('Tester present message is 0 bytes, should be 1')
        suppress_reply = data[0]
        return cls(suppress_reply, is_reply=is_reply)

    def render(self, is_reply=False):
        suppress_reply = self.params['suppress_reply']
        data = bytearray([suppress_reply])
        if len(data) < 1:
            raise InvalidMessage('Rendered tester present message is 0 bytes long')
        else:
            return super().render(data, is_reply=is_reply)

@register_uds_message
class ReadDataByIdentifier(UDSService):
    service_id = 0x22

    def __init__(self, identifier, userdata=None, is_reply=False):
        super().__init__(is_reply)
        self.params['identifier'] = identifier
        self.paramprint['identifier'] = lambda value: '0x{:04x}'.format(value)
        if userdata is not None:
            self.params['userdata'] = userdata
            self.paramprint['userdata'] = lambda value: utils.bytes_to_hex(value)

    @classmethod
    def parse(cls, data, is_reply=False):
        if len(data) < 2:
            raise InvalidMessage('Read data by identifier message is {} bytes, should be at least 2'.format(len(data)))
        identifier = utils.bytes_to_num(data[:2])
        userdata = None
        if is_reply is True:
            userdata = data[2:]
        return cls(identifier, userdata=userdata, is_reply=is_reply)

    def render(self, is_reply=False):
        identifier = self.params['identifier']
        data = bytearray(utils.num_to_bytes(identifier, 2))
        if is_reply is True:
            data += self.params.get('userdata', bytearray())
        if len(data) < 2:
            raise InvalidMessage('Rendered read data by identifier message is less than 2 bytes long')
        else:
            return super().render(data, is_reply=is_reply)

@register_uds_message
class DiagnosticSessionControl(UDSService):
    service_id = 0x10

    def __init__(self, subFuncton=0x01, is_reply=False):
        super().__init__(is_reply)
        self.params['subFuncton'] = subFuncton
        self.paramprint['subFuncton'] = lambda value: '0x{:02x}'.format(value)

    @classmethod
    def parse(cls, data, is_reply=False):
        if len(data) < 1:
            raise InvalidMessage('DiagnosticSessionControl message is 0 bytes, should be 1')
        subFuncton = data[0]
        return cls(subFuncton, is_reply=is_reply)

    def render(self, is_reply=False):
        subFuncton = self.params['subFuncton']
        data = bytearray([subFuncton])
        if len(data) < 1:
            raise InvalidMessage('Rendered DiagnosticSessionControl message is 0 bytes long')
        else:
            return super().render(data, is_reply=is_reply)

@register_uds_message
class Error(UDSService):
    GENERAL_REJECT = 0x10
    SERVICE_NOT_SUPPORTED = 0x11
    INVALID_FORMAT = 0x13
    BUSY_REPEAT_REQUEST = 0x21
    REQUEST_OUT_OF_RANGE = 0x31
    ACCESS_DENIED = 0x33
    RESPONSE_PENDING = 0x78

    MESSAGES = {
        GENERAL_REJECT: "General reject",
        SERVICE_NOT_SUPPORTED: "Service not supported",
        INVALID_FORMAT: "Invalid format",
        BUSY_REPEAT_REQUEST: "Busy - repeat request",
        REQUEST_OUT_OF_RANGE: "Request out of range",
        ACCESS_DENIED: "Access Denied",
        RESPONSE_PENDING: "Response Pending",
    }

    service_id = 0x3f

    def __init__(self, service_id_with_error, error_code, is_reply=False):
        super().__init__(is_reply)
        self.params['service_id_with_error'] = service_id_with_error
        self.paramprint['service_id_with_error'] = lambda value: '0x{:02x}'.format(value)
        self.params['error_code'] = error_code
        self.paramprint['error_code'] = lambda value: '0x{:02x}'.format(value)

    @classmethod
    def parse(cls, data, is_reply=False):
        if len(data) != 2:
            raise InvalidMessage('UDS error message is {} bytes, should be 2'.format(len(data)))
        service_id_with_error = data[0]
        error_code = data[1]
        return cls(service_id_with_error, error_code, is_reply=is_reply)

    def render(self, is_reply=False):
        service_id_with_error = self.params['service_id_with_error']
        error_code = self.params['error_code']
        data = bytearray([service_id_with_error, error_code])
        if len(data) < 2:
            raise InvalidMessage('Rendered read data by identifier message is less than 2 bytes long')
        else:
            return super().render(data, is_reply=is_reply)


def parse(message):
    return UDSService.parse(message)
