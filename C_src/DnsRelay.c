#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#define BUFFER_SIZE 1024
#define PORT 53
const char *SRV_IPADDR = "10.3.9.4";
const char *LOCAL_IPADDR = "127.0.0.1";

typedef struct DNSHEADER 
{
    unsigned short transactionID;   // 会话标识
    /**
     * flags(2 Bytes):cd
     * QR : 1 bit               0查询 / 1响应
     * Opcode : 4 bits          0标准查询 / 1反向查询 / 2服务器状态请求
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

void print_ipaddr(char *buf)
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
    int len = sizeof(clt);
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

        //printf("%s\n", buf + sizeof(dnsHeader));
        char temp[BUFFER_SIZE];
        strcpy(temp, buf + sizeof(dnsHeader) + 1);
        print_ipaddr(temp);

        /**
         * srvAddr : 查询用DNS服务器地址
         * 生成srvAddr的socket
         */
        struct sockaddr_in srvAddr;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            perror("socket error\n");
            exit(1);
        }

        /**
         * 配置查询用DNS服务器地址
         */
        bzero(&srvAddr, sizeof(srvAddr));   
        srvAddr.sin_family = AF_INET;       
        inet_aton(SRV_IPADDR, &srvAddr.sin_addr); 
        srvAddr.sin_port = htons(PORT);         

        /**
         * 向查询用DNS服务器地址发送查询报文
         * 并从其处接收响应报文
         */
        int i = sizeof(srvAddr);
        len = sendto(fd, buf, BUFFER_SIZE, 0, (struct sockaddr*)&srvAddr, sizeof(srvAddr));
        len = recvfrom(fd, buf, BUFFER_SIZE, 0, (struct sockaddr*)&srvAddr, &i);
        if (len < 0) {
            printf("recv error\n");
            exit(1);
        }

        /**
         * 将得到的响应信息返回给客户端
         */
        r = sendto(socketFd, buf, sizeof(buf), 0, (struct sockaddr*)&clt, sizeof(clt));
        if (r < 0) {
            perror("sendto error\n");
            exit(1);
        }
        close(fd);
    }
}


int main()
{   
    dns_relay();
}
