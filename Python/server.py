import sys
import struct
import getopt
import socketserver

from dns_resolver import DNSResolver

# 各类状态码对照表
QTYPE = {1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 12:'PTR', 15:'MX',
        16:'TXT', 17:'RP', 18:'AFSDB', 24:'SIG', 25:'KEY',
        28:'AAAA', 29:'LOC', 33:'SRV', 35:'NAPTR', 36:'KX',
        37:'CERT', 39:'DNAME', 41:'OPT', 42:'APL', 43:'DS',
        44:'SSHFP', 45:'IPSECKEY', 46:'RRSIG', 47:'NSEC',
        48:'DNSKEY', 49:'DHCID', 50:'NSEC3', 51:'NSEC3PARAM',
        55:'HIP', 99:'SPF', 249:'TKEY', 250:'TSIG', 251:'IXFR',
        252:'AXFR', 255:'*', 32768:'TA', 32769:'DLV'}
CLASS = { 1:'IN', 2:'CS', 3:'CH', 4:'Hesiod', 254:'None', 255:'*'}
QR = { 0:'QUERY', 1:'RESPONSE' }
RCODE = { 0:'None', 1:'Format Error', 2:'Server failure', 
                 3:'Name Error', 4:'Not Implemented', 5:'Refused', 6:'YXDOMAIN',
                 7:'YXRRSET', 8:'NXRRSET', 9:'NOTAUTH', 10:'NOTZONE'}
OPCODE = {0:'QUERY', 1:'IQUERY', 2:'STATUS', 5:'UPDATE' }

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

        # 分离请求报头中的状态码
        __flags__ = struct.unpack('>H', dns_server.response['data'][2:4])[0]
        flags = {
            'QR': __flags__ >> 15 & 0x0001,
            'OPCODE': __flags__ >> 11 & 0x000F,
            'AA': __flags__ >> 10 & 0x0001,
            'TC': __flags__ >> 9 & 0x0001,
            'RD': __flags__ >> 8 & 0x0001,
            'RA': __flags__ >> 7 & 0x0001,
            'RCODE': __flags__ & 0x000F
        }

        # 在屏幕上实时打印输出信息
        if output_level == 1:
            print("QNAME: %-s\nQTYPE: %-5s %-5s\tRCODE: %s" % (dns_server.request['question']['QNAME'],
                dns_server.request['question']['QTYPE'],
                QTYPE[dns_server.request['question']['QTYPE']],
                RCODE[flags['RCODE']]))
            print("RESULT: %s" % dns_server.response['answer']['ARDATA'])
            print("====================================================================")
        elif output_level == 2:
            print('#REQUEST#')
            print("Data:", dns_server.request['data'])
            print("Header: ", dns_server.request['header'])
            print("Question: ", dns_server.request['question'])
            print('#RESPONSE#')
            print("Data:", dns_server.response['data'])
            print("Header: ", dns_server.response['header'])
            print("Question: ", dns_server.response['question'])
            print("Answer:", dns_server.response['answer'])
            print("====================================================================")

        # 回传响应报文，完成 DNS 查询与中转
        request_socket.sendto(dns_server.response['data'], self.client_address)
        
if __name__ == "__main__":
    HOST, PORT = "localhost", 53
    server = socketserver.ThreadingUDPServer((HOST, PORT), DNSHandler)          # 启动多线程 UDP 服务器
    server.serve_forever()