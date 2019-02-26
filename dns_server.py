import struct
import socketserver
import dns.resolver

def parseDNSQuestion(request_data):
    question_qname = ''
    for i in request_data[13:len(request_data)-4]:
        if i < 32 and i != 0:
            question_qname += '.'
        elif i != 0:
            question_qname += chr(i)
    (question_qtype, question_qclass) = struct.unpack('>HH', request_data[-4:])
    return dict(QNAME=question_qname, QTYPE=question_qtype, QCLASS=question_qclass)

def parseDNSHeader(request_data):
    (header_id, header_flags, header_qdcount, header_ancount, header_nscount, header_arcount) = struct.unpack('>HHHHHH', request_data[0:12])
    return dict(ID=header_id, FLAGS=header_flags, QDCOUNT=header_qdcount, ANCOUNT=header_ancount, NSCOUNT=header_nscount, ARCOUNT=header_arcount)

class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        request_data = self.request[0].strip()
        request_socket = self.request[1]

        request_header = parseDNSHeader(request_data)
        request_question = parseDNSQuestion(request_data)

        print(request_data)
        print(request_question)

        respons = struct.pack('>HHHHHH', request_header['ID'], 33152, request_header['QDCOUNT'], 1, request_header['NSCOUNT'], request_header['ARCOUNT'])
        respons += bytes(request_data[12:])

        remote_resolver = dns.resolver.Resolver()
        remote_resolver.nameservers = ['223.5.5.5']
        remote_respons = remote_resolver.query(request_question['QNAME'], 'A')
        respons += struct.pack('>HHHLH', 49164, 1, 1, 600, 4)
        result = str(remote_respons[0]).split('.')
        respons += struct.pack('BBBB', int(result[0]), int(result[1]), int(result[2]), int(result[3]))

        request_socket.sendto(respons, self.client_address)
        
if __name__ == "__main__":
    HOST, PORT = "localhost", 53                      
    server = socketserver.UDPServer((HOST, PORT), DNSHandler)
    server.serve_forever()