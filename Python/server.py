import sys
import getopt
import socketserver

from dns_resolver import DNSResolver

class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        output_level = 0
        remote_server = '223.5.5.5'
        local_file = 'dnsrelay.txt'
        try:
            opts, args = getopt.getopt(sys.argv[1:], 'ho:f:s:', ['help', 'output=', 'filename=', 'server='])
            for opt, arg in opts:  
                if opt in ("-h", "--help"):
                    print("Usage:\ndnsrelay [-d|-dd] [filename] [dns_server_upaddr]")
                    sys.exit(1)
                elif opt in ("-o", "--output"):
                    output_level = int(arg)
                elif opt in ("-f", "--filename"):
                    local_file = arg
                elif opt in ("-s", "--server"):
                    remote_server = arg
        except getopt.GetoptError:
            print("Usage:\ndnsrelay [-d|-dd] [filename] [dns_server_upaddr]")
            sys.exit(1)

        request_data = self.request[0].strip()
        request_socket = self.request[1]

        dns_server = DNSResolver(request_data)

        request_header = dns_server.parseDNSHeader()
        request_question = dns_server.parseDNSQuestion()

        #respons = dns_server.queryLocalServer('dnsrelay.txt')
        #respons = dns_server.queryRemoteServer('223.5.5.5')
        respons = dns_server.queryIntegratedServer(local_file, remote_server)
        request_answer = dns_server.parseDNSAnswer()

        if output_level == 1:
            print("QNAME: %s\tQTYPE: %s" % (request_question['QNAME'], request_question['QTYPE']))
            if dns_server.result == '':
                print("RESULT: %s" % "NOTFOUND")
            else:
                print("RESULT: %s" % dns_server.result)
            print("====================================================================")
        elif output_level == 2:
            print("Header: ", request_header)
            print("Question: ", request_question)
            print("Answer:", request_answer)
            print("====================================================================")


        request_socket.sendto(respons, self.client_address)
        
if __name__ == "__main__":
    HOST, PORT = "localhost", 53              
    server = socketserver.ThreadingUDPServer((HOST, PORT), DNSHandler)
    server.serve_forever()