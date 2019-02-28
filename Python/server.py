import sys
import struct
import getopt
import socketserver

from dns_resolver import DNSResolver

# Socket 服务器 Handler
class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        output_level = 0
        local_file = 'dnsrelay.txt'         # 默认本地查询表文件名
        remote_server = '223.5.5.5'         # 默认远程转发服务器地址（阿里云 DNS）
        try:
            opts, args = getopt.getopt(sys.argv[1:], 'ho:f:s:', ['help', 'output=', 'filename=', 'server='])
            for opt, arg in opts: 
                # -h 或 --help 获得命令行使用帮助 
                if opt in ("-h", "--help"):
                    print("Usage:\ndnsrelay -d [0|1|2] -f [filename] -s [dns_server_upaddr]")
                    sys.exit(1)
                # -o 或 --output 获得输出信息，分为 0|1|2 三个等级
                elif opt in ("-o", "--output"):
                    output_level = int(arg)
                # -f 或 --filename 指定本地查询表文件
                elif opt in ("-f", "--filename"):
                    local_file = arg
                # -s 或 --server 指定远程查询服务器地址
                elif opt in ("-s", "--server"):
                    remote_server = arg
        except getopt.GetoptError:
            print("Usage:\ndnsrelay -d [0|1|2] -f [filename] -s [dns_server_upaddr]")
            sys.exit(1)

        request_data = self.request[0].strip()          # 接收二进制 DNS 查询报文数据
        request_socket = self.request[1]                # 保存本次 Socket 链接信息，用于回传响应报文

        # 进行 DNS 解析和查询
        dns_server = DNSResolver(request_data, local_file, remote_server)

        # 在屏幕上实时打印输出信息
        if output_level == 1:
            out = "QNAME: %s\nQTYPE: %-5s %-5s\tRCODE: %s\n" % (dns_server.request['question']['QNAME'],
                dns_server.request['question']['QTYPE'],
                dns_server.transFlag('TYPE', dns_server.request['question']['QTYPE']),
                dns_server.transFlag('RCODE', dns_server.request['question']['RCODE']))
            out += "RESULT: %s\n" % dns_server.response['answer']['ARDATA']
            out += "====================================================================\n"
        elif output_level == 2:
            out = "#REQUEST#\n"
            out += "Header:\n"
            out += "ID: %-5s\tFlags: %-5s\nQDCOUNT: %-2s\tANCOUNT: %-2s\tNSCOUNT: %-2s\tARCOUNT: %-2s\n" % (
                dns_server.request['header']['ID'], dns_server.request['header']['FLAGS'],
                dns_server.request['header']['QDCOUNT'], dns_server.request['header']['ANCOUNT'],
                dns_server.request['header']['NSCOUNT'], dns_server.request['header']['ARCOUNT'])
            out += "Question:\n"
            out += "QNAME: %s\nQTYPE: %-5s %-5s\tQCLASS: %s\n" % (
                dns_server.request['question']['QNAME'], dns_server.request['question']['QTYPE'],
                dns_server.transFlag('TYPE', dns_server.request['question']['QTYPE']),
                dns_server.transFlag('CLASS', dns_server.request['question']['QCLASS']))
            out += '\n#RESPONSE#\n'
            out += "Header:\n"
            out += "ID: %-5s\tFlags: %-5s\nQDCOUNT: %-2s\tANCOUNT: %-2s\tNSCOUNT: %-2s\tARCOUNT: %-2s\n" % (
                dns_server.response['header']['ID'], dns_server.response['header']['FLAGS'],
                dns_server.response['header']['QDCOUNT'], dns_server.response['header']['ANCOUNT'],
                dns_server.response['header']['NSCOUNT'], dns_server.response['header']['ARCOUNT'])
            out += "Question:\n"
            out += "QNAME: %s\nQTYPE: %-5s %-5s\tQCLASS: %s\n" % (
                dns_server.response['question']['QNAME'], dns_server.response['question']['QTYPE'],
                dns_server.transFlag('TYPE', dns_server.response['question']['QTYPE']),
                dns_server.transFlag('CLASS', dns_server.response['question']['QCLASS']))
            out += "Answer:\n"
            out += "ANAME: %s\nATYPE: %-5s %-5s\tACLASS: %-2s\tATTL: %-5s\tARDLENGTH: %-2s\n" % (
                dns_server.response['answer']['ANAME'], dns_server.response['answer']['ATYPE'],
                dns_server.transFlag('TYPE', dns_server.response['answer']['ATYPE']),
                dns_server.response['answer']['ACLASS'], dns_server.response['answer']['ATTL'],
                dns_server.response['answer']['ARDLENGTH'])
            out += "ARDATA: %s\n" % dns_server.response['answer']['ARDATA']
            out += "====================================================================\n"
        
        sys.stdout.write(out)

        # 回传响应报文，完成 DNS 查询与中转
        request_socket.sendto(dns_server.response['data'], self.client_address)
        
if __name__ == "__main__":
    HOST, PORT = "localhost", 53
    server = socketserver.ThreadingUDPServer((HOST, PORT), DNSHandler)          # 启动多线程 UDP 服务器
    server.serve_forever()