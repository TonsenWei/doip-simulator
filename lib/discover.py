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

import threading
from socket import socket, SOL_SOCKET, SO_BROADCAST, SOCK_DGRAM, IPPROTO_UDP, AF_INET, SO_REUSEADDR
from socket import timeout as SocketTimeout
import time

from . import doip

import logging
logger = logging.getLogger('discovery')


class DOIPDiscoverThread(threading.Thread):
    running = False

    def __init__(self, config, broadcast_interval=2, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.address = config['addresses']['discovery']
        self.config = config
        self.broadcast_interval = broadcast_interval
        self.daemon = True
        self.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        self.sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        self.sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

    def generate_announcement(self, address, config):
        vin = config['vin']
        mac = config['mac']
        return doip.VehicleAnnouncement(vin=vin, logical_address=address, eid=mac, gid=mac)

    def run(self, *args, **kwargs):
        logger.info('Starting UDP discovery thread')
        self.sock.bind(('', 13400))
        self.sock.settimeout(0.5)
        self.running = True
        self.announcement = self.generate_announcement(self.address, self.config).render()
        self.last_broadcast_time = time.time() - self.broadcast_interval
        while self.running:
            try:
                data, addr = self.sock.recvfrom(1024)
                message, used = doip.parse(bytearray(data))
                logger.debug("Message received from %s:%i : %s", addr[0], addr[1], message)
                if type(message) is doip.VehicleIdentityRequest:
                    logger.info('Vehicle identity requested by IP {}. '
                                'Responding with vehicle announcement.'.format(addr[0]))
                    self.sock.sendto(self.announcement, addr)
            except SocketTimeout:
                pass
            except Exception as err:
                logger.error('Error:', str(err))
                logger.exception('Trace:')

            now_time = time.time()
            if now_time - self.last_broadcast_time > self.broadcast_interval:
                self.last_broadcast_time = now_time
                self.sock.sendto(self.announcement, ('255.255.255.255', 13400))
