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

from lib import doip, uds, utils
import time
from socket import *
from socket import timeout as TimeoutException
import logging
import threading
import queue
# import serial

import os

SERIAL_PORT = os.environ.get("APP_SERIAL_PORT", '/dev/ttyAMA0')
SERIAL_BAUDRATE = int(os.environ.get("APP_SERIAL_BAUDRATE", 115200))

NETWORK_INTERFACE = os.environ.get("APP_NETWORK_INTERFACE")

ACCELERATOR_MULTIPLIER = float(os.environ.get("APP_ACCELERATOR_MULTIPLIER", 1.0))
BRAKE_MULTIPLIER = float(os.environ.get("APP_BRAKE_MULTIPLIER", 2.0)) # 2.0
STEERING_MULTIPLIER = float(os.environ.get("APP_STEERING_MULTIPLIER", 14)) # 14
STEERING_DEADZONE_CAR = int(os.environ.get("APP_STEERING_DEADZONE_CAR", 0)) # 0
STEERING_DEADZONE_XBOX = int(os.environ.get("APP_STEERING_DEADZONE_XBOX", 10000)) # 10000

logging.basicConfig(level=logging.WARNING)

def debug_parser(func):
    def print_args(*args, **kwargs):
        result = func(*args, **kwargs)
        logging.debug('>>>>>>', args, kwargs, result)
        return result
    return print_args

def parse_accelerator(data):
    if len(data) < 1:
        logging.error('Accelerator data length is too short to parse')
        return None
    magnitude = data[0]
    magnitude *= ACCELERATOR_MULTIPLIER
    magnitude = min(magnitude , 255)
    return int(magnitude)

def parse_brake_pressure(data):
    if len(data) < 2:
        logging.error('Brake pressure data length is too short to parse')
        return None
    magnitude = utils.bytes_to_num(data[:2])

    magnitude *= BRAKE_MULTIPLIER
    magnitude = int(magnitude) >> 8 # only use MSB
    magnitude = min(magnitude, 255)
    return int(magnitude)

def parse_steering_angle(data):
    if len(data) < 3:
        logging.error('Steering data length is too short to parse')
        return None
    magnitude = utils.bytes_to_num(data[:2])
    logging.debug("BEFORE MAGNITUDE %i (%x)", magnitude, magnitude)
    magnitude = max(magnitude, STEERING_DEADZONE_CAR)
    logging.debug("AFTER STEERING_DEADZONE_CAR %i (%x)", int(magnitude), int(magnitude))
    magnitude *= STEERING_MULTIPLIER
    logging.debug("AFTER STEERING_MULTIPLIER %i (%x)", int(magnitude), int(magnitude))
    magnitude = min(magnitude, 32700)
    magnitude = max(magnitude, STEERING_DEADZONE_XBOX)
    logging.debug("AFTER STEERING_DEADZONE_XBOX %i (%x)", int(magnitude), int(magnitude))
    if data[2] == 0:
        sign = -1
    else:
        sign = 1
    logging.debug("AFTER MAGNITUDE %i (%x)", int(magnitude), int(magnitude))
    return int(sign * magnitude)

config = {
    'datamap': {
        # target_address (hex) : {
        #   identifier (hex) : tuple(label (str), key (str), parser (func))
        # }
        0x3300: {
            0x3200: ('Dummy Accelerator', 'accelerator', parse_accelerator),
            0x3230: ('Dummy Brake', 'brake', parse_brake_pressure),
        },
        0x3301: {
            0x3250: ('Dummy Steering', 'steering', parse_steering_angle),
        }
    }
}


class DummyThread(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.daemon = True
        self.queue = queue.Queue()
        self.last_print = time.time()
        self.packets_sent = 0

    def run(self):
        while True:
            payload = self.queue.get()
            start = time.time()
            data = self.render(payload)
            if time.time() - self.last_print > 1:
                print('DATA OUT', data.encode(), '+ {} more'.format(self.packets_sent))
                self.last_print = time.time()
                self.packets_sent = 0
            else:
                self.packets_sent += 1
            time_taken = time.time() - start
            logging.debug("SERIAL OUT: %s  loop time is %.2f ms", data.strip(), time_taken * 1000)

    def render(self, payload):
        packed = []
        # TODO: add your own payload rendering here
        # packed += ['{:04x}'.format(payload.get(key, 0))]
        packed += ['{:04x}'.format(payload.get('steering', 0) & 0xFFFF)]
        packed += ['{:02x}'.format(payload.get('accelerator', 0))]
        packed += ['{:02x}'.format(payload.get('brake', 0))]
        return ''.join(packed) + '\n'

    def send(self, payload):
        self.queue.put(payload)


serial_thread = DummyThread()
serial_thread.start()

DOIP_TIMEOUT = 2
DOIP_SOURCE_ADDRESS = 0x0e80

# NETWORK LEVEL ERRORS
# sock.connect
# ECONNREFUSED - connection refused ->  delay 5 seconds -> back to detection mode - onnectionRefusedError
# ENETUNREACH - network unreachable - when there is no gateway to the iprange -> delay 5 seconds -> back to detection mode - OS Error
# ETIMEDOUT - timed out -> delay 5 seconds -> back to detection mode - TimeoutException
#
# sock.sendto
# ECONNRESET - connection reset by peer -> delay 1 second -> retry socket mode -> still fail -> delay 5 seconds -> back to detection mode
# ConnectionResetError
#
# sock.recvfrom
# ECONNREFUSED - connection refused ->  delay 5 seconds -> back to detection mode - ConnectionRefusedError

# DOIP ERRORS
# Generic NACK
# - 0x00 - incorrect pattern - close socket -> delay 1 second -> retry socket
# - 0x01 - unknown payload type - discard doip message -> skip
# - 0x02 - message too large - discard doip message -> skip
# - 0x03 - out of memory - discard doip message -> skip
# - 0x04 - invalid payload length - close socket -> delay 1 second -> retry socket
#
# Routing Activation Response
# - 0x00 - unknown source address - do not activate routing and close socket - RUNTIME ERROR
# - 0x01 - all sockets are active - do not activate routing and close socket -> delay 1 second -> retry socket
# .... blah blah blah
# - otherwise less than 0x10 = close socket -> retry after 5 seconds
#
# Diagnostic Message Nack
# - 0x02 - invalid source address - RUNTIME ERROR
# - 0x03 - unknown target address - WARN - skip
# - 0x04 - diagnostic message too large - RUNTIME ERROR
# - 0x05 - out of memory - RUNTIME ERROR
# - 0x06 - target unreachable - WARN - skip
# - 0x07 - unknown network - WARN - skip
# - 0x08 - transport protocol error - WARN - skip
#
# # UDS Errors
# Diagnostic Message / UDS Error
# - 0x10 - general reject - WARN - skip
# - 0x11 - service not supported - WARN - skip
# - 0x13 - invalid format - WARN - skip
# - 0x21 - busy repeat request - WARN - skip
# - 0x31 - request out of range - WARN - skip
# - 0x33 - access denied - WARN - skip
# - 0x78 - response pending - WARN - skip


def discover_doip():
    """Find the IP of the DOIP gateway"""
    # errors and their response:
    # - TimeoutException - cooldown before resend vehicle identity request
    # - network unreachable - caught by parent function
    s = socket(AF_INET, SOCK_DGRAM)
    s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
    if NETWORK_INTERFACE is not None:
        s.setsockopt(SOL_SOCKET, 25, str(NETWORK_INTERFACE + '\0').encode('utf-8'))
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    s.settimeout(DOIP_TIMEOUT)
    s.bind(('', 13400))

    logging.info("Looking for DOIP gateway...")

    while True:
        request = doip.VehicleIdentityRequest()
        logging.debug('SEND: %s', request)
        s.sendto(request.render(), ('255.255.255.255', 13400))
        try:
            start = time.time()
            while True:
                data, addr =  s.recvfrom(1024)
                data = bytearray(data)
                response, used = doip.parse(data)
                logging.debug('RECV: %s', response)
                if type(response) is doip.VehicleAnnouncement:
                    logging.info('Received Vehicle Announcement from %s!' % (addr[0]))
                    return addr[0]
                if time.time() - start > DOIP_TIMEOUT:
                    logging.warning('No vehicle announcement received. Requesting identity again immediately...')
                    break
        except timeout:
            logging.warning('No vehicle announcement received. Waiting 2 seconds before trying again...')
            time.sleep(2)


def setup_doip(gateway_addr):
    while True:
        try:
            s = socket(AF_INET, SOCK_STREAM)
            s.settimeout(DOIP_TIMEOUT)
            s.connect((gateway_addr, 13400))
        except TimeoutException:
            logging.error("DOIP session timed out while trying to connect. Reverting to discover mode...")
            return
        except ConnectionError as err:
            logging.error("%s while trying to connect. Reverting to discover mode...", type(err))
            return

        try:
            request = doip.RoutingActivationRequest(DOIP_SOURCE_ADDRESS)
            logging.debug('SEND: %s', request)
            s.send(request.render())
            data = s.recv(1024)
            if len(data) == 0:
                logging.error('Server send no data as a response to activation request. Retrying after 2 seconds...')
                time.sleep(DOIP_TIMEOUT)
                continue
            response, used = doip.parse(data)
            if type(response) is not doip.RoutingActivationResponse:
                logging.error("Routing activation response expected. Retrying after 2 seconds...")
                time.sleep(DOIP_TIMEOUT)
                continue
            if response.params['response_code'] != doip.RoutingActivationResponse.SUCCESSFUL_ACTIVATION:
                logging.error("Routing activation request was not successful. Retrying after 2 seconds...")
                time.sleep(DOIP_TIMEOUT)
                continue
            logging.debug('RECV: %s', response)
            logging.info('Routing activated successfully.')
            run_doip(s)
        except TimeoutException:
            logging.error("DOIP session timed out. Retrying after 2 seconds...")
            time.sleep(2)
        except ConnectionError as err:
            logging.error("A %s occurred. Retrying after 2 seconds...", type(err))
            time.sleep(2)


def run_doip(s):
    while True:
        data_payload = {}
        start = time.time()
        for target_address, identifiers in config['datamap'].items():
            for identifier, meta in identifiers.items():
                label, key, parser = meta
                logging.debug('Getting identifier 0x{:04x} ({})'.format(identifier, label))
                uds_request = uds.ReadDataByIdentifier(identifier)
                data = uds_request.render()
                request = doip.DiagnosticMessage(target_address, DOIP_SOURCE_ADDRESS, data)
                logging.debug("SEND %s", str(request))
                s.send(request.render())
                value = receive_doip(s, identifier, parser)
                if value is not None:
                    data_payload[key] = value
        if len(data_payload) > 0:
            serial_thread.send(data_payload)
        else:
            logging.warning('Data read loop result is empty')
        time_taken = time.time() - start
        logging.info('Data read loop time %.2f milliseconds with length %i', time_taken * 1000, len(data_payload))

def receive_doip(s, identifier, parser):
    # scenario #1 - packet 1 ... packet 2
    # scenario #2 - packet 1 + packet 2
    try:
        start = time.time()
        while time.time() - start < DOIP_TIMEOUT:
            data = s.recv(1024)
            while len(data) > 0:
                response, used = doip.parse(data)
                logging.debug("RECV %s %s", type(response), str(response))
                data = data[used:]
                if type(response) is doip.DiagnosticMessage:
                    uds_response = uds.parse(response.params['userdata'])
                    logging.debug("UDS %s %s", type(uds_response), str(uds_response))
                    if type(uds_response) is uds.ReadDataByIdentifier:
                        if identifier != uds_response.params['identifier']:
                            logging.error('Requested identifier 0x%04x does not match received identifier 0x%04x',
                                            identifier, uds_response.params['identifier'])
                            return None
                        value = parser(uds_response.params['userdata'])
                        if value is None:
                            logging.error('Parser for identifier 0x%04x returned none for value "%s"',
                                            identifier, utils.bytes_to_hex(uds_response.params['userdata']))
                            return None
                        else:
                            return value
                    elif type(uds_response) is uds.Error:
                        error_code = uds_response.params['error_code']
                        if error_code != uds.Error.RESPONSE_PENDING:
                            logging.error('Service ID 0x%02x returned error code %02x - %s',
                                        uds_response.params['service_id_with_error'],
                                        error_code,
                                        uds_response.MESSAGES.get(error_code, "UNKNOWN"))
                            return None
                        else:
                            logging.info('UDS: Response is pending, please wait for a response')
                    else:
                        logging.info("Unexpected UDS payload received: %s", response)
                elif type(response) is doip.DiagnosticMessageAck:
                    logging.debug('Diagnostic message acknowledgement received')
                elif type(response) is doip.DiagnosticMessageNegativeAck:
                    nack_code = response.params['nack_code']
                    logging.error('Diagnostics NACK %02x - %s', nack_code,
                                response.MESSAGES.get(nack_code, "UNKNOWN"))
                    if nack_code == doip.DiagnosticMessageNegativeAck.INVALID_SOURCE_ADDR:
                        source_address = response.params['source_address']
                        raise Exception('Fatal error - Source address 0x%04x is not accepted by DOIP gateway', source_address)
                    return None
                else:
                    logging.info("Unexpected DOIP payload received: %s", response)
        raise TimeoutException('DOIP read operation did not get a timely response')
    except (doip.MessageTypeNotSupported, uds.ServiceIDNotSupported) as err:
        logging.error("%s. Skipping...", err)
        return None
    except (doip.InvalidMessage, uds.InvalidMessage) as err:
        logging.error("%s. Skipping...", err)
        return None


while True:
    try:
        gateway_addr = discover_doip()
        setup_doip(gateway_addr)
    except OSError as err:
        logging.error("Error: %s", str(err))
        time.sleep(5)
