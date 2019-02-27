import struct
import dns.resolver

class DNSResolver():
    def __init__(self, request_data):
        self.request_data = request_data
        self.result = ''
                
    def parseDNSHeader(self):
        (header_id, header_flags, header_qdcount, header_ancount, header_nscount, header_arcount) = struct.unpack('>HHHHHH', self.request_data[0:12])
        self.request_header = dict(ID=header_id, FLAGS=header_flags, QDCOUNT=header_qdcount, ANCOUNT=header_ancount, NSCOUNT=header_nscount, ARCOUNT=header_arcount)
        return self.request_header

    def parseDNSQuestion(self):
        question_qname = ''
        for i in self.request_data[13:-4]:
            if i < 32 and i != 0:
                question_qname += '.'
            elif i != 0:
                question_qname += chr(i)
        (question_qtype, question_qclass) = struct.unpack('>HH', self.request_data[-4:])
        self.request_question = dict(QNAME=question_qname, QTYPE=question_qtype, QCLASS=question_qclass)
        return self.request_question

    def queryLocalServer(self, local_file):
        with open('./' + local_file, 'r') as rule_file:
            for rule in rule_file.readlines():
                if rule.strip().split(' ')[1] == self.request_question['QNAME']:
                    self.result = rule.split(' ')[0]
                    break

        return self.result

    def queryRemoteServer(self, server_ip):
        remote_resolver = dns.resolver.Resolver()
        remote_resolver.nameservers = [server_ip]
        remote_respons = remote_resolver.query(self.request_question['QNAME'], 'A')
        self.result = str(remote_respons[0])

        return self.result

    def queryIntegratedServer(self):
        self.queryLocalServer('dnsrelay.txt')
        if not self.result:
            self.queryRemoteServer('223.5.5.5')

        if self.result == '' or self.result == '0.0.0.0':
            flags = 33155
            answer = 0
        else:
            flags = 33152
            answer = 1
        respons = struct.pack('>HHHHHH', self.request_header['ID'], flags, self.request_header['QDCOUNT'], answer, self.request_header['NSCOUNT'], self.request_header['ARCOUNT'])
        respons += bytes(self.request_data[12:])

        if answer != 0:
            respons += struct.pack('>HHHLH', 49164, 1, 1, 600, 4)
            ip = self.result.split('.')
            respons += struct.pack('BBBB', int(ip[0]), int(ip[1]), int(ip[2]), int(ip[3]))

        return respons