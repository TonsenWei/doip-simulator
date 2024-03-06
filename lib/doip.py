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

from . import utils

import logging
logger = logging.getLogger('doip')


class DOIPException(Exception):
    pass

class InvalidMessage(DOIPException):
    pass

class MessageTypeNotSupported(DOIPException):
    pass


REGISTERED_PAYLOADS = {}
def register_doip_message(cls):
    REGISTERED_PAYLOADS[cls.payload_type] = cls
    return cls

class DOIPMessage(object):
    payload_type = None

    def __init__(self):
        self.params = {}
        self.paramprint = {}

    @classmethod
    def parse(cls, data):
        # check preamble
        version = data[0]
        if version != data[1] ^ 0xFF:
            raise InvalidMessage('Invalid version preamble')
        payload_type = utils.bytes_to_num(data[2:4])
        if payload_type not in REGISTERED_PAYLOADS:
            raise MessageTypeNotSupported('Message type "{:04x} not supported"'.format(payload_type))
        written_length = utils.bytes_to_num(data[4:8])
        actual_length = len(data[8:])
        # TODO: try and work out how to parse out multiple objects from stream
        if actual_length < written_length:
            raise InvalidMessage('Length field with value {} does not match '
                                 'actual length {}'.format(written_length, actual_length))
        return REGISTERED_PAYLOADS[payload_type].parse(data[8:8+written_length]), written_length + 8

    def render(self, data):
        if self.payload_type is None:
            raise Exception('DOIPMessage subclass has no payload_type value')
        header = bytearray([0x2, 0xfd])
        header += bytearray(utils.num_to_bytes(self.payload_type, 2))
        header += bytearray(utils.num_to_bytes(len(data), 4))
        return header + data

    def __str__(self):
        result = '{} [0x{:04x}]:'.format(self.__class__.__name__, self.payload_type)
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

@register_doip_message
class VehicleIdentityRequest(DOIPMessage):
    payload_type = 0x0001

    @classmethod
    def parse(cls, data):
        if len(data) > 0:
            raise InvalidMessage('Read message is {} instead of 0 bytes long'.format(len(data)))
        return cls()

    def render(self):
        return super().render(bytearray())

@register_doip_message
class VehicleAnnouncement(DOIPMessage):
    NO_ACTION_REQUIRED = 0x0

    payload_type = 0x0004

    def __init__(self, vin, logical_address, eid, gid, action_required=NO_ACTION_REQUIRED):
        super().__init__()
        self.params['vin'] = vin
        self.params['logical_address'] = logical_address
        self.params['eid'] = eid
        self.params['gid'] = gid
        self.params['action_required'] = action_required
        self.paramprint['vin'] = lambda value: value.decode()
        self.paramprint['logical_address'] = lambda value: '0x{:04x}'.format(value)
        self.paramprint['eid'] = lambda value: '0x{:06x}'.format(value)
        self.paramprint['gid'] = lambda value: '0x{:06x}'.format(value)
        self.paramprint['action_required'] = lambda value: '0x{:02x}'.format(value)

    @classmethod
    def parse(cls, data):
        if len(data) != 32:
            raise InvalidMessage('Read vehicle announcement message is {} '
                                 'instead of 32 bytes long'.format(len(data)))
        vin = data[0:17].rstrip(b'\0')
        logical_address = utils.bytes_to_num(data[17:19])
        eid = utils.bytes_to_num(data[19:25])
        gid = utils.bytes_to_num(data[25:31])
        action_required = data[31]
        return cls(vin, logical_address, eid, gid, action_required)

    def render(self):
        vin = self.params['vin']
        logical_address = self.params['logical_address']
        eid = self.params['eid']
        gid = self.params['gid']
        action_required = self.params['action_required']

        encoded_vin = vin.encode('utf-8')
        data = encoded_vin.ljust(17, b'\0')
        data += bytearray(utils.num_to_bytes(logical_address, 2))
        data += bytearray(utils.num_to_bytes(eid, 6))
        data += bytearray(utils.num_to_bytes(gid, 6))
        data += bytearray([action_required])
        if len(data) != 32:
            raise InvalidMessage('Rendered vehicle announcement message is {} '
                                 'instead of 32 bytes long'.format(len(data)))
        else:
            return super().render(data)

@register_doip_message
class RoutingActivationRequest(DOIPMessage):
    DEFAULT_ACTIVATION_TYPE = 0x0

    payload_type = 0x0005

    def __init__(self, source_address, activation_type=DEFAULT_ACTIVATION_TYPE):
        super().__init__()
        self.params['source_address'] = source_address
        self.params['activation_type'] = activation_type
        self.paramprint['source_address'] = lambda value: '0x{:04x}'.format(value)
        self.paramprint['activation_type'] = lambda value: '0x{:02x}'.format(value)

    @classmethod
    def parse(cls, data):
        if len(data) != 7:
            raise InvalidMessage('Read routing activation request is {} '
                                 'instead of 11 bytes long'.format(len(data)))
        source_addr = utils.bytes_to_num(data[:2])
        activation_type = data[2]
        # bytes 3-11 are reserved and not used
        return cls(source_addr, activation_type)

    def render(self):
        source_address = self.params['source_address']
        activation_type = self.params['activation_type']
        data = bytearray(utils.num_to_bytes(source_address, 2))
        data += bytearray([activation_type])
        # add the reserved bytes back in
        data += bytearray([0] * 8)
        if len(data) != 11:
            raise InvalidMessage('Rendered routing activation request is {} '
                                 'instead of 11 bytes long'.format(len(data)))
        else:
            return super().render(data)

@register_doip_message
class RoutingActivationResponse(DOIPMessage):
    ERROR_UNKNOWN_SOURCE = 0x00
    ERROR_NO_FREE_SOCKETS = 0x01
    ERROR_SOURCE_MISMATCH = 0x02
    ERROR_SOURCE_IN_USE = 0x03
    SUCCESSFUL_ACTIVATION = 0x10

    payload_type = 0x0006

    def __init__(self, target_address, source_address, response_code=SUCCESSFUL_ACTIVATION):
        super().__init__()
        self.params['target_address'] = target_address
        self.params['source_address'] = source_address
        self.params['response_code'] = response_code
        self.paramprint['target_address'] = lambda value: '0x{:04x}'.format(value)
        self.paramprint['source_address'] = lambda value: '0x{:04x}'.format(value)
        self.paramprint['response_code'] = lambda value: '0x{:02x}'.format(value)

    @classmethod
    def parse(cls, data):
        if len(data) != 13:
            raise InvalidMessage('Read routing activation response is {} '
                                 'instead of 13 bytes long'.format(len(data)))
        target_address = utils.bytes_to_num(data[:2])
        source_address = utils.bytes_to_num(data[2:4])
        response_code = data[4]
        # bytes 3-11 are reserved and not used
        return cls(target_address, source_address, response_code)

    def render(self):
        target_address = self.params['target_address']
        source_address = self.params['source_address']
        response_code = self.params['response_code']
        data = bytearray(utils.num_to_bytes(target_address, 2))
        data += bytearray(utils.num_to_bytes(source_address, 2))
        data += bytearray([response_code])
        # add the reserved bytes back in
        data += bytearray([0] * 8)
        if len(data) != 13:
            raise InvalidMessage('Rendered routing activation response is {} '
                                 'instead of 13 bytes long'.format(len(data)))
        else:
            return super().render(data)

@register_doip_message
class DiagnosticMessage(DOIPMessage):
    payload_type = 0x8001

    def __init__(self, target_address, source_address, userdata):
        super().__init__()
        self.params['source_address'] = source_address
        self.params['target_address'] = target_address
        self.params['userdata'] = userdata
        self.paramprint['source_address'] = lambda value: '0x{:04x}'.format(value)
        self.paramprint['target_address'] = lambda value: '0x{:04x}'.format(value)
        self.paramprint['userdata'] = lambda value: utils.bytes_to_hex(value)

    @classmethod
    def parse(cls, data):
        if len(data) < 5:
            raise InvalidMessage('Read diagnostic message is less than 5 bytes long')
        source_address = utils.bytes_to_num(data[:2])
        target_address = utils.bytes_to_num(data[2:4])
        userdata = data[4:]
        # bytes 3-11 are reserved and not used
        return cls(target_address, source_address, userdata)

    def render(self):
        source_address = self.params['source_address']
        target_address = self.params['target_address']
        userdata = self.params['userdata']
        data = bytearray(utils.num_to_bytes(source_address, 2))
        data += bytearray(utils.num_to_bytes(target_address, 2))
        data += bytearray(userdata)
        if len(data) < 5:
            raise InvalidMessage('Rendered diagnostic message is less than 5 bytes long')
        else:
            return super().render(data)

@register_doip_message
class DiagnosticMessageAck(DOIPMessage):
    MESSAGE_ACKNOWLEDGE = 0x0

    payload_type = 0x8002

    def __init__(self, source_address, target_address, ack_code=MESSAGE_ACKNOWLEDGE):
        super().__init__()
        self.params['source_address'] = source_address
        self.params['target_address'] = target_address
        self.params['ack_code'] = ack_code
        self.paramprint['source_address'] = lambda value: '0x{:04x}'.format(value)
        self.paramprint['target_address'] = lambda value: '0x{:04x}'.format(value)
        self.paramprint['ack_code'] = lambda value: '0x{:02x}'.format(value)

    @classmethod
    def parse(cls, data):
        if len(data) < 5:
            raise InvalidMessage('Read diagnostic message ack less than 5 bytes long')
        source_address = utils.bytes_to_num(data[:2])
        target_address = utils.bytes_to_num(data[2:4])
        ack_code = data[4]
        # dont care about context
        return cls(source_address, target_address, ack_code)

    def render(self):
        source_address = self.params['source_address']
        target_address = self.params['target_address']
        ack_code = self.params['ack_code']
        data = bytearray(utils.num_to_bytes(source_address, 2))
        data += bytearray(utils.num_to_bytes(target_address, 2))
        data += bytearray([ack_code])
        if len(data) < 5:
            raise InvalidMessage('Rendered diagnostic message ack less than 5 bytes long')
        else:
            return super().render(data)

@register_doip_message
class DiagnosticMessageNegativeAck(DOIPMessage):
    INVALID_SOURCE_ADDR = 0x02
    UNKNOWN_TARGET_ADDR = 0x03
    MESSAGE_TOO_LARGE = 0x04
    OUT_OF_MEMORY = 0x05

    MESSAGES = {
        INVALID_SOURCE_ADDR: 'Invalid source address',
        UNKNOWN_TARGET_ADDR: 'Unknown target address',
        MESSAGE_TOO_LARGE: 'Message too large',
        OUT_OF_MEMORY: 'Out of memory'
    }

    payload_type = 0x8003

    def __init__(self, source_address, target_address, nack_code):
        super().__init__()
        self.params['source_address'] = source_address
        self.params['target_address'] = target_address
        self.params['nack_code'] = nack_code
        self.paramprint['source_address'] = lambda value: '0x{:04x}'.format(value)
        self.paramprint['target_address'] = lambda value: '0x{:04x}'.format(value)
        self.paramprint['nack_code'] = lambda value: '0x{:02x}'.format(value)

    @classmethod
    def parse(cls, data):
        if len(data) < 5:
            raise InvalidMessage('Read diagnostic message negative ack less than 5 bytes long')
        source_address = utils.bytes_to_num(data[:2])
        target_address = utils.bytes_to_num(data[2:4])
        nack_code = data[4]
        # dont care about context
        return cls(source_address, target_address, nack_code)

    def render(self):
        source_address = self.params['source_address']
        target_address = self.params['target_address']
        nack_code = self.params['nack_code']
        data = bytearray(utils.num_to_bytes(source_address, 2))
        data += bytearray(utils.num_to_bytes(target_address, 2))
        data += bytearray([nack_code])
        if len(data) < 5:
            raise InvalidMessage('Rendered diagnostic message negative ack less than 5 bytes long')
        else:
            return super().render(data)

def parse(message):
    return DOIPMessage.parse(message)
