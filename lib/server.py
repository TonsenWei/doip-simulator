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

import asyncio
import logging
import time

from . import uds
from . import doip

from . import simulator as sim

logger = logging.getLogger("server")

class DOIPServer(object):

    def __init__(self, config, simulator):
        self.simulator = simulator
        self.config = config

    async def start_server(self):
        server = await asyncio.start_server(
            self.handle_doip_session, '0.0.0.0', 13400)

        addr = server.sockets[0].getsockname()
        print(f'Serving on {addr}')

        try:
            async with server:
                await server.serve_forever()
        except KeyboardInterrupt:
            pass

    def serve_forever(self):
        asyncio.run(self.start_server())

    # switch to class to decrease indentation
    async def handle_doip_session(self, reader, writer):
        client_addr = writer.get_extra_info('peername')
        logger.info('Connection established with %s', client_addr)

        routing_activated = False
        try:
            while True:
                data = await reader.read(1024)

# eg code
# https://stackoverflow.com/questions/2184181/decoding-tcp-packets-using-python
                # TODO: read as a stream -> header first
                # TODO: handle bad preamble -> close socket
                # TODO: handle bad length -> close socket
                # TODO: handle other message types -> generic nack unknown payload
                if len(data) == 0:
                    logger.info('Client %s disconnected', client_addr)
                    break

                print(f"{data = }")
                request, used = doip.parse(data)
                logger.debug("Message received from %s : %s", client_addr, request)

                if not routing_activated:
                    if type(request) is doip.RoutingActivationRequest:
                        response = doip.RoutingActivationResponse(request.params['source_address'],
                                                                  self.config['addresses']['discovery'])
                        outdata = response.render()
                        writer.write(outdata)
                        await writer.drain()
                        routing_activated = True
                        continue # to the next incoming packet
                    else:
                        logger.error('Error: Received non-activation request message before activation: %s', request)
                        logger.error('       Closing socket...')
                        break
                else:
                    if type(request) is doip.DiagnosticMessage:
                        source_address = request.params['source_address']
                        target_address = request.params['target_address']
                        userdata = request.params['userdata']

                        if not self.simulator.has_target_address(target_address):
                            logger.error('Error: target_address 0x{:02x} is unknown'.format(target_address))
                            response = doip.DiagnosticMessageNegativeAck(source_address, target_address,
                                                    doip.DiagnosticMessageNegativeAck.UNKNOWN_TARGET_ADDR)
                            writer.write(response.render())
                            await writer.drain()
                            continue
                        else:
                            response = doip.DiagnosticMessageAck(source_address, target_address)
                            writer.write(response.render())
                            await writer.drain()

                        try:
                            uds_request = uds.parse(userdata)
                            if type(uds_request) is uds.TesterPresent:
                                uds_reply = uds_request  # send it straight back
                            elif type(uds_request) is uds.ReadDataByIdentifier:
                                identifier = uds_request.params['identifier']
                                try:
                                    readdata = self.simulator.read_value(target_address, identifier)
                                    uds_reply = uds.ReadDataByIdentifier(identifier, userdata=readdata, is_reply=True)
                                except sim.IdentifierNotFound as err:
                                    logger.error('Error: %s', str(err))
                                    uds_reply = uds.Error(uds.ReadDataByIdentifier.service_id, uds.Error.REQUEST_OUT_OF_RANGE)
                            elif type(uds_request) is uds.DiagnosticSessionControl:
                                uds_reply = uds.DiagnosticSessionControl(is_reply=True)
                            else:
                                logger.error('Service ID 0x{:02x} is not implemented on server'.format(uds_request.service_id))
                                uds_reply = uds.Error(uds.ReadDataByIdentifier.service_id, uds.Error.SERVICE_NOT_SUPPORTED)
                            # Make response message
                            response = doip.DiagnosticMessage(source_address, target_address, uds_reply.render(is_reply=True))
                        except uds.ServiceIDNotSupported as err:
                            logger.error('Error: %s', str(err))
                            uds_reply = uds.Error(userdata[0], uds.Error.SERVICE_NOT_SUPPORTED)
                            response = doip.DiagnosticMessage(source_address, target_address, uds_reply.render(is_reply=True))
                        except uds.InvalidMessage as err:
                            logger.error('Error: %s', str(err))
                            uds_reply = uds.Error(userdata[0], uds.Error.INVALID_FORMAT)
                            response = doip.DiagnosticMessage(source_address, target_address, uds_reply.render(is_reply=True))
                        writer.write(response.render())  # response to client
                        await writer.drain()

        except Exception as err:
            logger.error('Error in session with %s', client_addr)
            logger.exception('Stack trace:')
        finally:
            writer.close()
