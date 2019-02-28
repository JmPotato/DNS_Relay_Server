import struct
import socket

# 各类状态码对照表
TYPE = {1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 12:'PTR', 15:'MX',
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

class DNSResolver():
    # 构造函数，初始化数据结构
    def __init__(self, request_data, local_file='dnsrelay.txt', remote_server='223.5.5.5'):
        # 请求报文
        self.request = {
            'data': request_data,
            'flags': self.parseFlags(request_data),
            'header': self.parseDNSHeader(request_data),
            'question': self.parseDNSQuestion(request_data)
        }

        # 响应报文
        response_data = self.queryIntegratedServer(local_file, remote_server)
        self.response = {
            'data': response_data,
            'flags': self.parseFlags(response_data),
            'header': self.parseDNSHeader(response_data),
            'question': self.parseDNSQuestion(response_data),
            'answer': self.parseDNSAnswer(response_data)
        }

    # 翻译状态码
    def transFlag(self, flag_name, flag_value):
        try:
            if flag_name == 'TYPE':
                message = TYPE[flag_value]
            elif flag_name == 'CLASS':
                message = CLASS[flag_value]
            elif flag_name == 'QR':
                message = QR[flag_value]
            elif flag_name == 'RCODE':
                message = RCODE[flag_value]
            elif flag_name == 'OPCODE':
                message = OPCODE[flag_value]
        except:
            message = 'NULL'
        finally:
            return message

    # 分离报头中的状态码
    def parseFlags(self, bytes_flags):
        __flags__ = struct.unpack('>H', bytes_flags[2:4])[0]
        flags = {
            'QR': __flags__ >> 15 & 0x0001,
            'OPCODE': __flags__ >> 11 & 0x000F,
            'AA': __flags__ >> 10 & 0x0001,
            'TC': __flags__ >> 9 & 0x0001,
            'RD': __flags__ >> 8 & 0x0001,
            'RA': __flags__ >> 7 & 0x0001,
            'RCODE': __flags__ & 0x000F
        }
        return flags
    
    '''
    Header format

    0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|  opcode   |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    '''
    # 报文 Header 解析
    def parseDNSHeader(self, bytes_data):
        try:
            (header_id, header_flags, header_qdcount, header_ancount, header_nscount, header_arcount) = struct.unpack('>HHHHHH', bytes_data[0:12])
            return dict(ID=header_id, FLAGS=header_flags, QDCOUNT=header_qdcount, ANCOUNT=header_ancount, NSCOUNT=header_nscount, ARCOUNT=header_arcount)
        except:
            return {}

    '''
    Question format

    0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     ...                       |
    |                    QNAME                      |
    |                     ...                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QTYPE                      |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QCLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    '''
    # 报文 Question 解析
    def parseDNSQuestion(self, bytes_data):
        # 还原出正常的字符串域名
        try:
            question_qname = ''
            count = 13
            for i in bytes_data[13:]:
                count += 1
                if i < 32 and i != 0:
                    question_qname += '.'
                elif i != 0:
                    question_qname += chr(i)
                elif i == 0:
                    break
            (question_qtype, question_qclass) = struct.unpack('>HH', bytes_data[count:count+4])
            return dict(QNAME=question_qname, QTYPE=question_qtype, QCLASS=question_qclass)
        except:
            return {}

    '''
    Answer/Authority/Additional format

    0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NAME                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    TYPE                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    CLASS                      |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    TTL                        |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    RDLENGTH                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    RDATA                      |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    '''
    # 报文 Answer 解析
    def parseDNSAnswer(self, bytes_data):
        try:
            if self.response['flags'] == 0:
                return dict(ANAME=0, ATYPE=0, ACLASS=0, ATTL=0, ARDLENGTH=0, ARDATA='0.0.0.0')
            (answer_qtype, answer_qclass, answer_ttl, answer_rdlength, 
            answer_data_1, answer_data_2, answer_data_3, answer_data_4) = struct.unpack('>HHLHBBBB', bytes_data[-14:])
            return dict(ANAME=49164, ATYPE=answer_qtype, ACLASS=answer_qclass, ATTL=answer_ttl, ARDLENGTH=answer_rdlength, 
            ARDATA=str(answer_data_1) + '.' + str(answer_data_2) + '.' + str(answer_data_3) + '.' + str(answer_data_4))
        except:
            return dict(ANAME=0, ATYPE=0, ACLASS=0, ATTL=0, ARDLENGTH=0, ARDATA='0.0.0.0')

    # 本地对照表查询
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

        # 区分查询成功失败情况
        if self.ip_result == '' or self.ip_result == '0.0.0.0':
            flags = 33155
            answer = 0
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

    # 远程服务器中转查询
    def queryRemoteServer(self, remote_server):
        # UDP 连接远程 DNS 服务器进行中转查询
        remote_resolver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        remote_resolver.sendto(self.request['data'], (remote_server, 53))
        response_data = remote_resolver.recvfrom(1024)[0]
        remote_resolver.close()

        return response_data

    # 综合查询函数
    def queryIntegratedServer(self, local_file, remote_server):
        response_data = self.queryLocalServer(local_file)           # 先进行本地查询
        if self.request['question']['QTYPE'] == 1 and self.ip_result == '':
            response_data = self.queryRemoteServer(remote_server)       # 本地未查询到记录后转发远程服务器查询

        return response_data