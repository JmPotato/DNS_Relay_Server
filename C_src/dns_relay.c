#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#define BUFFER_SIZE 1024
#define PORT 53
#define IPSIZE 4
const char *SRV_IPADDR = "10.3.9.4";
const char *LOCAL_IPADDR = "127.0.0.1";

typedef struct DNSHEADER 
{
    unsigned short transactionID;   // 会话标识
    /**
     * flags(2 Bytes):cd
     * QR : 1 bit               0查询 / 1响应
     * Opcode : 4 bit           0标准查询 / 1反向查询 / 2服务器状态请求
     * AA : 1 bit               表示授权回答
     * TC : 1 bit               表示可以截断
     * RD : 1 bit               表示期望递归查询
     * RA : 1 bit               表示可用递归查询
     * Z : 3 bits               保留
     * Rcode : 4 bit            返回码：0没有差错 / 2服务器错误 / 3名字差错
     */ 
    unsigned short flags;           // 标志
    unsigned short quesNumber;      // Questions
    unsigned short ansNumber;       // Answer RRs
    unsigned short authNumber;      // Authority RRs
    unsigned short addNumber;       // Additional RRs

} dnsHeader;

typedef struct DNSQUERY
{
    /**
     * main type:
     * A(1) : IPv4
     * AAAA(28) : IPv6
     */
    unsigned short type;

    /**
     * IN(1) : Internet
     */
    unsigned short classes;
} dnsQuery;

#pragma pack(push, 1)
typedef struct DNSRR
{
    unsigned short type;
    unsigned short classes;
    unsigned int ttl;
    unsigned short data_length;
} dnsRR;
#pragma pack(pop)

/**
 * 将域名以二进制数据转换为字符串形式（带.）
 */
void to_domain_name(char *buf)
{
    char *p = buf;
    while (*p != 0) {
        if (*p >= '!')
            p++;
        else {
            *p = '.';
            p++;
        }
    }
    printf("%s\n", buf);
}

/**
 * 查询 IP - 域名 对照表
 * 输入域名与存放ip地址的内存的指针
 * 并将ip地址转换为字节形式
 * 查找成功返回1，查找失败返回0
 */
int lookup_int_text(char *dn, char *ip)
{
    int flag = 0;
    FILE *fp;
    char ipAddr[BUFFER_SIZE];
    char domainName[BUFFER_SIZE];
    if ((fp = fopen("dnsrelay.txt", "r")) == NULL) {
        printf("file open error\n");
        exit(1);
    }
    while (!feof(fp)) {
        fgets(ipAddr, 1024, fp);
        for (int i = 0; i < BUFFER_SIZE; i++) {
            if (ipAddr[i] == ' ') {
                ipAddr[i] = '\0';
                break;
            }
        }
        strcpy(domainName, ipAddr + strlen(ipAddr) + 1);
        if (domainName[strlen(domainName) - 1] == '\n')
            domainName[strlen(domainName) - 1] = '\0';
        else
            domainName[strlen(domainName)] = '\0';
        

        //printf("111:%s!\n", domainName);
        //printf("222:%s!\n", dn);
        //printf("333:%d\n", strcmp(dn, domainName));
        // 找到了域名，得到ip地址

        if (strcmp(dn, domainName) == 0) {

            // 得到ip地址
            char *h = ipAddr;
            char *p = ipAddr;
            int i = 0;
            //printf("%s\n", ipAddr);
            while (*p != '\0') {
                if (*p == '.') {
                    *p = '\0';
                    ip[i] = (char)atoi(h);
                    i++;
                    h = p + 1;
                }
                p++;
            }
            ip[i] = atoi(h);
            flag = 1;
            return flag;
        }
    }
    return flag;
}

/**
 * 构造响应报文
 */
void creat_msg_manully(char *buf, char *ip)
{
    dnsHeader *header = (dnsHeader *)buf;
    dnsRR *rr;
    header->flags = htons(0x8180);
    header->ansNumber = htons(1);
    char *dn = buf + sizeof(dnsHeader);
    //printf("%lu\n", strlen(dn));
    //dnsQuery *query = (dnsQuery *)(dn + strlen(dn) + 1);
    //query->type = htons((unsigned short)1);
    //query->classes = htons((unsigned short)1);
    char *name = dn + strlen(dn) + 1 + sizeof(dnsQuery);
    unsigned short *_name = (unsigned short *)name;
    *_name = htons((unsigned short)0xC00C);
    rr = (dnsRR *)(name + 2);
    rr->type = htons(1);
    rr->classes = htons(1);
    rr->ttl = htons(0xFFF);
    rr->data_length = htons(4);
    char *data = (char *)rr + 10;
    *data = *ip;
    *(data + 1) = *(ip + 1);
    *(data + 2) = *(ip + 2);
    *(data + 3) = *(ip + 3);
}

/**
 * dns relay
 */
void dns_relay()
{
    /**
     * buf : 临时存储发出/接收的数据
     * socketFd : 本地服务器的socket
     * srv : 存储本地服务器地址
     * clt : 存储客户端地址
     * r : 临时存储各种返回值
     */
    char buf[BUFFER_SIZE];
    int socketFd, r;
    struct sockaddr_in srv;
    struct sockaddr_in clt;

    /**
     * 配置本地服务器地址
     */
    bzero(&srv, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port = htons(PORT);
    inet_aton(LOCAL_IPADDR, &srv.sin_addr);

    /**
     * 配置客户端地址
     */
    clt.sin_family = AF_INET;
    clt.sin_port = htons(PORT);
    inet_aton(LOCAL_IPADDR, &clt.sin_addr);
    //clt.sin_addr.s_addr = htonl(INADDR_ANY);
    //printf("0\n");
    /**
     * 创建socket
     * 将socket与本地服务器地址绑定
     */
    socketFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketFd < 0) {
        perror("socket error\n");
        exit(1);
    }
    //printf("1\n");
    r = bind(socketFd, (struct sockaddr *)&srv, sizeof(srv));
    if (r < 0) {
        perror("bind error\n");
        exit(1);
    }
    //printf("2\n");

    /**
     * 需要完善：
     * 实时生成调试信信息
     */

    // 持续运行
    unsigned int len = sizeof(clt);
    while(1) {

        /**
         * 从客户端接收数据
         */
        memset(buf, 0, BUFFER_SIZE);
        r = recvfrom(socketFd, buf, BUFFER_SIZE, 0, (struct sockaddr *)&clt, &len);
        if (r < 0) {
            perror("recvfrom error\n");
            exit(1);
        }
        
        /**
         * 得到发送查询请求的域名
         */
        //printf("%s\n", buf + sizeof(dnsHeader));
        char *temp = (char *)malloc(BUFFER_SIZE);
        char *ip = (char *)malloc(IPSIZE);
        strcpy(temp, buf + sizeof(dnsHeader) + 1);
        to_domain_name(temp);
        int find_dn_ip = lookup_int_text(temp, ip);
        printf("find: %d\n", find_dn_ip);
        free(temp);
        printf("%u.%u.%u.%u\n", *ip & 0x000000ff, *(ip + 1) & 0x000000ff, *(ip + 2) & 0x000000ff, *(ip + 3) & 0x000000ff);

        /**
         * 在 IP - 域名 对照表中找到，手动构造响应报文
         */
        if (find_dn_ip) {
            creat_msg_manully(buf, ip);
            free(ip);
        }

        /**
         * 在 IP - 域名 对照表中没有找到，中继给外部dns服务器
         */
        else if (!find_dn_ip) {
            /**
             * DnsSrvAddr : 查询用DNS服务器地址
             * 生成DnsSrvAddr的socket
             */
            struct sockaddr_in DnsSrvAddr;
            int fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (fd < 0) {
                perror("socket error\n");
                exit(1);
            }

            /**
             * 配置查询用DNS服务器地址
             */
            bzero(&DnsSrvAddr, sizeof(DnsSrvAddr));   
            DnsSrvAddr.sin_family = AF_INET;       
            inet_aton(SRV_IPADDR, &DnsSrvAddr.sin_addr); 
            DnsSrvAddr.sin_port = htons(PORT);         

            /**
            * 向查询用DNS服务器地址发送查询报文
            * 并从其处接收响应报文
            */
            unsigned int i = sizeof(DnsSrvAddr);
            len = sendto(fd, buf, BUFFER_SIZE, 0, (struct sockaddr*)&DnsSrvAddr, sizeof(DnsSrvAddr));
            len = recvfrom(fd, buf, BUFFER_SIZE, 0, (struct sockaddr*)&DnsSrvAddr, &i);
            if (len < 0) {
                printf("recv error\n");
                exit(1);
            }
            close(fd);
        }

        /**
         * 将得到的响应信息返回给客户端
         */
        r = sendto(socketFd, buf, sizeof(buf), 0, (struct sockaddr*)&clt, sizeof(clt));
        if (r < 0) {
            perror("sendto error\n");
            exit(1);
        }    
    }
}


int main()
{   
    dns_relay();
}
