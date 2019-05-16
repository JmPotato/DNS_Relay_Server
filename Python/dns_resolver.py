import struct   #处理字节流，将字节流转化为整数类型
import socket

# 各类状态码对照表
QR = { 0:'QUERY', 1:'RESPONSE' }                                        #报头中QR字段，0表示查询报，1表示响应报
OPCODE = {0:'QUERY', 1:'IQUERY', 2:'STATUS', 5:'UPDATE' }               #报头中OPCODE字段，通常值为0（标准查询）
RCODE = { 0:'None', 1:'Format Error', 2:'Server failure',               #报头中RCODE字段，响应码(Response coded)，仅用于响应报文。值为0表示没有差错，值为3表示名字差错
                 3:'Name Error', 4:'Not Implemented', 5:'Refused', 6:'YXDOMAIN',
                 7:'YXRRSET', 8:'NXRRSET', 9:'NOTAUTH', 10:'NOTZONE'}
CLASS = { 1:'IN', 2:'CS', 3:'CH', 4:'Hesiod', 254:'None', 255:'*'}      #资源记录中CLASS字段，通常为IN(1)，指Internet数据                                                                
TYPE = {1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 12:'PTR', 15:'MX',           #资源记录中TYPE字段，表明资源的类型
        16:'TXT', 17:'RP', 18:'AFSDB', 24:'SIG', 25:'KEY',
        28:'AAAA', 29:'LOC', 33:'SRV', 35:'NAPTR', 36:'KX',
        37:'CERT', 39:'DNAME', 41:'OPT', 42:'APL', 43:'DS',
        44:'SSHFP', 45:'IPSECKEY', 46:'RRSIG', 47:'NSEC',
        48:'DNSKEY', 49:'DHCID', 50:'NSEC3', 51:'NSEC3PARAM',
        55:'HIP', 99:'SPF', 249:'TKEY', 250:'TSIG', 251:'IXFR',
        252:'AXFR', 255:'*', 32768:'TA', 32769:'DLV'}

class DNSResolver():
    # 构造函数，初始化数据结构
    def __init__(self, request_data, local_file='dnsrelay.txt', remote_server='223.5.5.5'):   #阿里公用DNS服务器
        # 请求报文
        self.request_data = request_data
        self.request = {
            'data': request_data,
            'flags': self.parseFlags(request_data),
            'header': self.parseDNSHeader(request_data),
            'question': self.parseDNSQuestion(request_data)
        }

        # 响应报文
        self.response_data = self.queryIntegratedServer(local_file, remote_server)
        self.response = {
            'data': self.response_data,
            'flags': self.parseFlags(self.response_data),
            'header': self.parseDNSHeader(self.response_data),
            'question': self.parseDNSQuestion(self.response_data),
            'answer': self.parseDNSAnswer(self.response_data)
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
        __flags__ = struct.unpack('>H', bytes_flags[2:4])[0]  #'>'表示字节顺序是big-endian，也就是网络序，'H'表示此处将报头的第3和4个字节变为2字节无符号整数
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
            (header_id, header_flags, header_qdcount, header_ancount, header_nscount, header_arcount) = struct.unpack('>HHHHHH', bytes_data[0:12])  #将报头的前12个字节，每两个字节一组变为2字节无符号整数
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
            length = bytes_data[12]
            index = 12
            count = 1
            while(count <= length):
                question_qname += chr(bytes_data[index+count])
                count += 1
                if(count > length and bytes_data[index+count] != 0):
                    question_qname += '.'
                    length = bytes_data[index+count]
                    index = index + count
                    count = 1
            (question_qtype, question_qclass) = struct.unpack('>HH', bytes_data[index+count+1:index+count+1+4])
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
            if self.parseDNSHeader(bytes_data)['ANCOUNT'] == 0:
                return dict(ANAME=0, ATYPE=0, ACLASS=0, ATTL=0, ARDLENGTH=0, ARDATA='0.0.0.0')
            (answer_qtype, answer_qclass, answer_ttl, answer_rdlength,  #2字节TYPE,2字节CLASS，4字节TTL，2字节RDLENGTH，对类型1（TYPE A记录）最后字段是4字节的IP地址  
            answer_data_1, answer_data_2, answer_data_3, answer_data_4) = struct.unpack('>HHLHBBBB', bytes_data[-14:])
            return dict(ANAME=49164, ATYPE=answer_qtype, ACLASS=answer_qclass, ATTL=answer_ttl, ARDLENGTH=answer_rdlength, 
            ARDATA=str(answer_data_1) + '.' + str(answer_data_2) + '.' + str(answer_data_3) + '.' + str(answer_data_4))
        except:
            return dict(ANAME=0, ATYPE=0, ACLASS=0, ATTL=0, ARDLENGTH=0, ARDATA='0.0.0.0')

    # 本地对照表查询
    def queryLocalServer(self, local_file):
        self.ip_result = ''
        if self.request['question']['QTYPE'] == 1:   #如果查询类型为查询主机名对应的IP地址
            try:
                with open('./' + local_file, 'r') as rule_file:  #打开本地对照表，逐行查找
                    for rule in rule_file.readlines():
                        try:
                            entry = rule.strip().split(' ')
                            if entry[1] == self.request['question']['QNAME']:
                                self.ip_result = entry[0]     #查找到域名，填写对应IP地址
                                break
                        except:
                            continue
            except FileNotFoundError:
                self.ip_result = ''

        # 区分查询成功失败情况
        if self.ip_result == '' or self.ip_result == '0.0.0.0':
            flags = 33155   #查询失败，多3？
            answer = 0
        else:
            flags = 33152   #查询成功
            answer = 1     
            
        response_data = struct.pack('>HHHHHH', self.request['header']['ID'], flags, self.request['header']['QDCOUNT'], answer, self.request['header']['NSCOUNT'], self.request['header']['ARCOUNT'])
        response_data += bytes(self.request['data'][12:])                #加上Question问题区域
        if answer != 0:
            response_data += struct.pack('>HHHLH', 49164, 1, 1, 600, 4)  #加上Answer回答区域的前面的字段
            ip = self.ip_result.split('.')
            response_data += struct.pack('BBBB', int(ip[0]), int(ip[1]), int(ip[2]), int(ip[3])) #加上Answer回答区域最后的资源数据（即IP地址）字段
        return response_data

    # 远程服务器中转查询
    def queryRemoteServer(self, remote_server):
        # UDP 连接远程 DNS 服务器进行中转查询
        remote_resolver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  #服务器之间网络通信，数据报式socket , for UDP
        remote_resolver.sendto(self.request['data'], (remote_server, 53))   #DNS服务器使用53端口
        response_data = remote_resolver.recvfrom(1024)[0]                   #接受UDP套接字的数据，只用数据部分，舍弃发送方的地址
        remote_resolver.close()

        return response_data

    # 综合查询函数
    def queryIntegratedServer(self, local_file, remote_server):
        response_data = self.queryLocalServer(local_file)               # 先进行本地查询
        if self.ip_result == '':
            response_data = self.queryRemoteServer(remote_server)       # 本地未查询到记录向其他DNS服务器发出查询

        return response_data