import sys
import getopt           #解析命令行参数的模块
import socketserver     #多线程服务器

from dns_resolver import DNSResolver    #导入dns_resolver类中的DNSResolver类，用来进行DNS报文的解析和查询

# Socket 服务器 Handler
class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        output_level = 1                    # 默认输出等级为1
        local_file = 'dnsrelay.txt'         # 默认本地查询表文件名
        remote_server = '223.5.5.5'         # 默认远程转发服务器地址（阿里云DNS服务器）
        try:
            opts, args = getopt.getopt(sys.argv[1:], 'ho:f:s:', ['help', 'output=', 'filename=', 'server='])  #获取命令行参数，过滤掉第一个参数(脚本的文件名)
            for opt, arg in opts:  #opts是一个两元组的列表。每个元素为：(选项串,附加参数)
                # -o 或 --output 获得输出信息，分为 1|2 两个等级
                if opt in ("-o", "--output"):
                    output_level = int(arg)
                # -f 或 --filename 指定本地查询的对照表文件
                elif opt in ("-f", "--filename"):
                    local_file = arg
                # -s 或 --server 指定远程查询DNS服务器地址
                elif opt in ("-s", "--server"):
                    remote_server = arg
        except getopt.GetoptError: 
            print("Usage:\n -o [1|2] -f [filename] -s [dns_server_upaddr]")  #打印使用方法，并退出
            sys.exit(1)

        request_data = self.request[0].strip()          # 接收二进制 DNS 查询报文数据
        request_socket = self.request[1]                # 保存本次 Socket 链接信息，用于回传响应报文

        # 进行 DNS 解析和查询
        dns_server = DNSResolver(request_data, local_file, remote_server)

        # 在屏幕上实时打印报文的信息
        if output_level == 1:  #调试输出级别为1
            out = "QNAME: %s\nQTYPE: %-5s %-5s\tRCODE: %s\n" % (dns_server.request['question']['QNAME'],
                dns_server.request['question']['QTYPE'],
                dns_server.transFlag('TYPE', dns_server.request['question']['QTYPE']),
                dns_server.transFlag('RCODE', dns_server.response['flags']['RCODE']))
            out += "RESULT: %s\n" % dns_server.response['answer']['ARDATA']
            out += "====================================================================\n"
        else:                  #调试输出级别为2
            out = "Client: %s:%s\n" % (self.client_address[0], self.client_address[1])
            out += "#REQUEST#\n"
            out += "Header:\n"
            out += "ID: %-5s\tFlags: %-5s\nQDCOUNT: %-2s\tANCOUNT: %-2s\tNSCOUNT: %-2s\tARCOUNT: %-2s\n" % (
                dns_server.request['header']['ID'], dns_server.request['header']['FLAGS'],
                dns_server.request['header']['QDCOUNT'], dns_server.request['header']['ANCOUNT'],
                dns_server.request['header']['NSCOUNT'], dns_server.request['header']['ARCOUNT'])
            out += "Question:\n"
            out += "QNAME: %s\nQTYPE: %-5s %-5s\tQCLASS: %s\tRCODE: %s\n" % (
                dns_server.request['question']['QNAME'], dns_server.request['question']['QTYPE'],
                dns_server.transFlag('TYPE', dns_server.request['question']['QTYPE']),
                dns_server.transFlag('CLASS', dns_server.request['question']['QCLASS']),
                dns_server.transFlag('RCODE', dns_server.request['flags']['RCODE']))
            out += '\n#RESPONSE#\n'
            out += 'DATA:\n'
            for byte in dns_server.response_data:
                out += str(hex(byte)) + ' '
            out += '\n'
            out += "Header:\n"
            out += "ID: %-5s\tFlags: %-5s\nQDCOUNT: %-2s\tANCOUNT: %-2s\tNSCOUNT: %-2s\tARCOUNT: %-2s\n" % (
                dns_server.response['header']['ID'], dns_server.response['header']['FLAGS'],
                dns_server.response['header']['QDCOUNT'], dns_server.response['header']['ANCOUNT'],
                dns_server.response['header']['NSCOUNT'], dns_server.response['header']['ARCOUNT'])
            out += "Question:\n"
            out += "QNAME: %s\nQTYPE: %-5s %-5s\tQCLASS: %s\tRCODE: %s\n" % (
                dns_server.response['question']['QNAME'], dns_server.response['question']['QTYPE'],
                dns_server.transFlag('TYPE', dns_server.response['question']['QTYPE']),
                dns_server.transFlag('CLASS', dns_server.response['question']['QCLASS']),
                dns_server.transFlag('RCODE', dns_server.response['flags']['RCODE']))
            if dns_server.response['header']['ANCOUNT']:
                out += "Answer:\n"
                out += "ANAME: %s\nATYPE: %-5s %-5s\tACLASS: %-2s\tATTL: %-5s\tARDLENGTH: %-2s\n" % (
                    dns_server.response['answer']['ANAME'], dns_server.response['answer']['ATYPE'],
                    dns_server.transFlag('TYPE', dns_server.response['answer']['ATYPE']),
                    dns_server.response['answer']['ACLASS'], dns_server.response['answer']['ATTL'],
                    dns_server.response['answer']['ARDLENGTH'])
                out += "ARDATA: %s\n" % dns_server.response['answer']['ARDATA']
            out += "====================================================================\n"
        
        sys.stdout.write(out)  #报文信息打印到控制台

        # 回传响应报文，完成DNS查询与中转
        request_socket.sendto(dns_server.response['data'], self.client_address)
        
if __name__ == "__main__": 
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'ho:f:s:', ['help', 'output=', 'filename=', 'server='])
        for opt, arg in opts: 
            # -h 或 --help 获得命令行使用帮助 
            if opt in ("-h", "--help"):
                print("Usage:\n -o [1|2] -f [filename] -s [dns_server_upaddr]")
                sys.exit(1)
    except getopt.GetoptError:
        print("Usage:\n -o [1|2] -f [filename] -s [dns_server_upaddr]") #打印使用方法，并退出
        sys.exit(1)
    HOST, PORT = "127.0.0.1", 53
    server = socketserver.ThreadingUDPServer((HOST, PORT), DNSHandler)  #启动多线程 UDP 服务器，每个客户端请求连接到服务器时，服务器都会创建新线程专门负责处理当前客户端的所有请求。
    server.serve_forever()                                              #循环，持续不断监听端口