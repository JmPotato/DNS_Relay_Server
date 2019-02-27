import struct
import dns.resolver

class DNSResolver():
    def __init__(self, request_data):
        self.request_data = request_data
        self.result = ''
        self.answer = b''
                
    def parseDNSHeader(self):
        (header_id, header_flags, header_qdcount, header_ancount, header_nscount, header_arcount) = struct.unpack('>HHHHHH', self.request_data[0:12])
        self.header = dict(ID=header_id, FLAGS=header_flags, QDCOUNT=header_qdcount, ANCOUNT=header_ancount, NSCOUNT=header_nscount, ARCOUNT=header_arcount)
        return self.header

    def parseDNSQuestion(self):
        question_qname = ''
        for i in self.request_data[13:-4]:
            if i < 32 and i != 0:
                question_qname += '.'
            elif i != 0:
                question_qname += chr(i)
        (question_qtype, question_qclass) = struct.unpack('>HH', self.request_data[-4:])
        self.question = dict(QNAME=question_qname, QTYPE=question_qtype, QCLASS=question_qclass)
        return self.question

    def parseDNSAnswer(self):
        try:
            (answer_qname, answer_qtype, answer_qclass, answer_ttl, answer_rdlength) = struct.unpack('>HHHLH', self.answer)
            self.answer = dict(ANAME=answer_qname, ATYPE=answer_qtype, ACLASS=answer_qclass, ATTL=answer_ttl, ARDLENGTH=answer_rdlength, RDATA=self.result)
        except:
            self.answer = {}
        return self.answer

    def queryLocalServer(self, local_file):
        try:
            with open('./' + local_file, 'r') as rule_file:
                for rule in rule_file.readlines():
                    if rule.strip().split(' ')[1] == self.question['QNAME']:
                        self.result = rule.split(' ')[0]
                        break
        except:
            self.result = ''

        return self.result

    def queryRemoteServer(self, remote_server):
        remote_resolver = dns.resolver.Resolver()
        remote_resolver.nameservers = [remote_server]
        try:
            remote_respons = remote_resolver.query(self.question['QNAME'], 'A')
            self.result = str(remote_respons[0])
        except:
            self.result = ''

        return self.result

    def queryIntegratedServer(self, local_file='dnsrelay.txt', remote_server='223.5.5.5'):
        if self.question['QTYPE'] == 1:
            self.queryLocalServer(local_file)
            if not self.result:
                self.queryRemoteServer(remote_server)

        if self.result == '' or self.result == '0.0.0.0':
            flags = 33155
            answer = 0
            self.result == ''
        else:
            flags = 33152
            answer = 1

        self.respons = struct.pack('>HHHHHH', self.header['ID'], flags, self.header['QDCOUNT'], answer, self.header['NSCOUNT'], self.header['ARCOUNT'])
        self.respons += bytes(self.request_data[12:])
        if answer != 0:
            self.answer = struct.pack('>HHHLH', 49164, 1, 1, 600, 4)
            self.respons += self.answer
            ip = self.result.split('.')
            self.respons += struct.pack('BBBB', int(ip[0]), int(ip[1]), int(ip[2]), int(ip[3]))

        return self.respons