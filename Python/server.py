import socketserver

from dns_resolver import DNSResolver

class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        request_data = self.request[0].strip()
        request_socket = self.request[1]

        dns_server = DNSResolver(request_data)

        request_header = dns_server.parseDNSHeader()
        request_question = dns_server.parseDNSQuestion()

        print(request_header)
        print(request_question)

        #respons = dns_server.queryLocalServer('dnsrelay.txt')
        #respons = dns_server.queryRemoteServer('223.5.5.5')
        respons = dns_server.queryIntegratedServer()
        
        request_socket.sendto(respons, self.client_address)
        
if __name__ == "__main__":
    HOST, PORT = "localhost", 53              
    server = socketserver.ThreadingUDPServer((HOST, PORT), DNSHandler)
    server.serve_forever()