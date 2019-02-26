import struct
import socketserver

def parseDNSHeader(request_data):
    question_qname = ''
    for i in request_data[13:len(request_data)-4]:
        if i < 32 and i != 0:
            question_qname += '.'
        elif i != 0:
            question_qname += chr(i)
    (question_qtype, question_qclass) = struct.unpack('>HH', request_data[-4:])
    return dict(QNAME=question_qname, QTYPE=question_qtype, QCLASS=question_qclass)

def parseDNSQuestion(request_data):
    (header_id, header_flags, header_qdcount, header_ancount, header_nscount, header_arcount) = struct.unpack('>HHHHHH', request_data[0:12])
    return dict(ID=header_id, FLAGS=header_flags, QDCOUNT=header_qdcount, ANCOUNT=header_ancount, NSCOUNT=header_nscount, ARCOUNT=header_arcount)

class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        request_header = parseDNSHeader(self.request[0])
        request_question = parseDNSQuestion(self.request[0])
 
if __name__ == "__main__":
    HOST, PORT = "localhost", 53                      
    server = socketserver.UDPServer((HOST, PORT), DNSHandler)
    server.serve_forever()