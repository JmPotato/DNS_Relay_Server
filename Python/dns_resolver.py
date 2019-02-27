import struct
import socket
import dns.resolver

class DNSResolver():
    def __init__(self, request_data, local_file='dnsrelay.txt', remote_server='223.5.5.5'):
        self.request = {
            'data': request_data,
            'header': self.parseDNSHeader(request_data),
            'question': self.parseDNSQuestion(request_data)
        }
        response_data = self.queryIntegratedServer(local_file, remote_server)
        self.response = {
            'data': response_data,
            'header': self.parseDNSHeader(response_data),
            'question': self.parseDNSQuestion(response_data),
            'answer': self.parseDNSAnswer(response_data)
        }
                
    def parseDNSHeader(self, bytes_data):
        try:
            (header_id, header_flags, header_qdcount, header_ancount, header_nscount, header_arcount) = struct.unpack('>HHHHHH', bytes_data[0:12])
            return dict(ID=header_id, FLAGS=header_flags, QDCOUNT=header_qdcount, ANCOUNT=header_ancount, NSCOUNT=header_nscount, ARCOUNT=header_arcount)
        except:
            return {}

    def parseDNSQuestion(self, bytes_data):
        try:
            question_qname = ''
            for i in bytes_data[13:-4]:
                if i < 32 and i != 0:
                    question_qname += '.'
                elif i != 0:
                    question_qname += chr(i)
            (question_qtype, question_qclass) = struct.unpack('>HH', bytes_data[-4:])
            return dict(QNAME=question_qname, QTYPE=question_qtype, QCLASS=question_qclass)
        except:
            return {}

    def parseDNSAnswer(self, bytes_data):
        try:
            (answer_qtype, answer_qclass, answer_ttl, answer_rdlength, 
            answer_data_1, answer_data_2, answer_data_3, answer_data_4) = struct.unpack('>HHLHBBBB', bytes_data[-14:])
            return dict(ANAME=49164, ATYPE=answer_qtype, ACLASS=answer_qclass, ATTL=answer_ttl, ARDLENGTH=answer_rdlength, 
            ARDATA=str(answer_data_1) + '.' + str(answer_data_2) + '.' + str(answer_data_3) + '.' + str(answer_data_4))
        except:
            return {}

    def queryLocalServer(self, local_file):
        self.ip_result = ''
        if self.request['question']['QTYPE'] == 1:
            try:
                with open('./' + local_file, 'r') as rule_file:
                    for rule in rule_file.readlines():
                        if rule.strip().split(' ')[1] == self.request['question']['QNAME']:
                            self.ip_result = rule.split(' ')[0]
                            break
            except:
                self.ip_result = ''

        if self.ip_result == '' or self.ip_result == '0.0.0.0':
            flags = 33155
            answer = 0
            self.ip_result == ''
        else:
            flags = 33152
            answer = 1

        response_data = struct.pack('>HHHHHH', self.request['header']['ID'], flags, self.request['header']['QDCOUNT'], answer, self.request['header']['NSCOUNT'], self.request['header']['ARCOUNT'])
        response_data += bytes(self.request['data'][12:])
        if answer != 0:
            response_data += struct.pack('>HHHLH', 49164, 1, 1, 600, 4)
            ip = self.ip_result.split('.')
            response_data += struct.pack('BBBB', int(ip[0]), int(ip[1]), int(ip[2]), int(ip[3]))
        return response_data

    def queryRemoteServer(self, remote_server):
        remote_resolver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        remote_resolver.sendto(self.request['data'], (remote_server, 53))
        response_data = remote_resolver.recvfrom(1024)[0]
        remote_resolver.close()

        return response_data

    def queryIntegratedServer(self, local_file, remote_server):
        response_data = self.queryLocalServer(local_file)
        if self.ip_result == '':
            response_data = self.queryRemoteServer(remote_server)

        return response_data