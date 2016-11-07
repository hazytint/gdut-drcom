#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#ifdef WIN32
    #include <winsock2.h>
    //#define SOCKET int
    typedef int socklen_t;
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #define SOCKET int
	#define INVALID_SOCKET -1
#endif

#ifdef __WITH_POLARSSL__
    #include <polarssl/md5.h>
    #include <polarssl/md4.h>
    #include <polarssl/sha1.h>

    #define _MD5(data, len, _md5) md5(data, len, _md5)
    #define _MD4(data, len, _md4) md4(data, len, _md4)
    #define _SHA1(data, len, _sha1) sha1(data, len, _sha1)
#elif __WITH_GCRYPT__
    #include <gcrypt.h>

    #define _MD5(data, len, _md5) gcry_md_hash_buffer(GCRY_MD_MD5, _md5, data, len)
    #define _MD4(data, len, _md4) gcry_md_hash_buffer(GCRY_MD_MD4, _md4, data, len)
    #define _SHA1(data, len, _sha1) gcry_md_hash_buffer(GCRY_MD_SHA1, _sha1, data, len)
#elif __WITH_OPENSSL__
    #include <openssl/md5.h>
    #include <openssl/md4.h>
    #include <openssl/sha.h>

    #define _MD5(data, len, _md5) MD5(data, len, _md5)
    #define _MD4(data, len, _md4) MD4(data, len, _md4)
    #define _SHA1(data, len, _sha1) SHA1(data, len, _sha1)
#else
    #include "crypt/md5.h"
    #include "crypt/md4.h"
    #include "crypt/sha1.h"

    #define _MD5(data, len, _md5) md5(data, len, _md5)
    #define _MD4(data, len, _md4) md4(data, len, _md4)
    #define _SHA1(data, len, _sha1) sha1(data, len, _sha1)
#endif

#include "config.h"
/****local functions****/


static int make_keep_alive2_pkt1(uint8_t *buf, uint8_t cnt, uint8_t *key, uint8_t type, int is_first);

static void gen_ka1_checksum(uint8_t *checksum, uint8_t *seed, uint8_t mode);

//static int32_t drcomCRC32(char *data, int len);
static void print_as_hex(uint8_t *buf, int len);
/****local functions****/


int auth(void)
{
#ifdef WIN32
    WORD sockVersion = MAKEWORD(2,2);
    WSADATA wsaData;
    if(WSAStartup(sockVersion, &wsaData)!=0)
    {
        return 0;
    }
#endif

    /*variavles of packets*/
    uint8_t pkt_data[1024] = {0};      //packet data buf
    int length;                         //packet data length
    /*variavles of packets*/

    /*variables used in keep alive2 paket*/
    uint8_t kp2_cnt = 0x01;
    uint8_t ka2_key[4] = {0};
    int ka2_is_first;
    /*variables used in keep alive2 paket*/

    struct sockaddr_in remote_addr;
    struct sockaddr_in local_addr;
    int retry_cnt;

    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
#ifdef WIN32
    remote_addr.sin_addr.S_un.S_addr = inet_addr(drcom_config.remote_ip);
#else
    remote_addr.sin_addr.s_addr = inet_addr(drcom_config.remote_ip);
#endif
    remote_addr.sin_port=htons(drcom_config.remote_port);

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
#ifdef WIN32
    local_addr.sin_addr.S_un.S_addr = inet_addr("0.0.0.0");
#else
    local_addr.sin_addr.s_addr = inet_addr("0.0.0.0");
#endif
    local_addr.sin_port=htons(drcom_config.remote_port);

    SOCKET client_sockfd;
    if ((client_sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
    {
        fprintf(stderr, "error!\n");
        fflush(stderr);
        return -1;
    }

    socklen_t sin_size;
    sin_size = sizeof(struct sockaddr_in);
    bind(client_sockfd, (struct sockaddr *) &local_addr, sin_size);
#ifdef WIN32
    int timeout = 2000;
#else

    struct timeval timeout;
    timeout.tv_sec=2;
    timeout.tv_usec=0;
#endif
    setsockopt(client_sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(struct timeval));


HEART_BEAT_START:
    fprintf(stdout, "gdut-drcom heart-beat started!\n\n");
    fflush(stdout);
    ka2_is_first = 1;
    kp2_cnt = 0;
    srand((unsigned int)time(NULL));

    while (1)
    {
        retry_cnt = 0;

        while (1)
        {
            length = make_keep_alive2_pkt1(pkt_data, kp2_cnt, ka2_key, kp2_cnt == 0 ? 1 : kp2_cnt, ka2_is_first);
            sendto(client_sockfd, pkt_data, length, 0,\
                (struct sockaddr *) &remote_addr, sizeof(remote_addr));
            fprintf(stdout, "<==[sended kap2_1 request %d] len = %d\n",\
                    kp2_cnt, length);
            fflush(stdout);
            print_as_hex(pkt_data, length);

            if (retry_cnt > 5)
            {
                goto HEART_BEAT_START;
            }
            memset(pkt_data, 0x00, 1024);
            if ((length = recvfrom(client_sockfd, pkt_data, 1024, 0,\
                (struct sockaddr *) &remote_addr, &sin_size)) == -1)
            {
                fprintf(stdout, "recv kap2_1 timeout, retry %d!\n", retry_cnt++);
                fflush(stdout);
            }
            else
            {
                if (pkt_data[0] == 0x07 && pkt_data[2] == 0x10)
                {
                    fprintf(stdout, "==>[recieved kap2_1 response %d] len = %d\n",\
                            kp2_cnt, length);
                    fflush(stdout);
                    print_as_hex(pkt_data, length);
                    ka2_is_first = 0;
                    kp2_cnt++;
                    continue;
                } else if (pkt_data[0] == 0x07 && pkt_data[2] == 0x28) {
                    fprintf(stdout, "==>[recieved kap2_1 response %d] len = %d\n",\
                    kp2_cnt, length);
                    fflush(stdout);
                    print_as_hex(pkt_data,length);
                    break;
                } else {
                    fprintf(stdout, "==>[recieved kap2_1 response %d] unexpected\n", kp2_cnt);
                }
            }
        }

        retry_cnt = 1;
        while (1)
        {
            length = make_keep_alive2_pkt1(pkt_data, kp2_cnt, ka2_key, 1, ka2_is_first);
            sendto(client_sockfd, pkt_data, length, 0,\
                (struct sockaddr *) &remote_addr, sizeof(remote_addr));
            fprintf(stdout, "<==[sended kap2_2 request %d] len = %d\n",\
                    kp2_cnt, length);
            fflush(stdout);
            print_as_hex(pkt_data, length);

            if (retry_cnt > 5)
            {
                goto HEART_BEAT_START;
            }
            memset(pkt_data, 0x00, 1024);
            if ((length = recvfrom(client_sockfd, pkt_data, 1024, 0,\
                (struct sockaddr *) &remote_addr, &sin_size)) == -1)
            {
                fprintf(stdout, "recv kap2_2 timeout, retry %d!\n", retry_cnt++);
                fflush(stdout);
            }
            else
            {
                if (pkt_data[0] == 0x07)
                {
                    fprintf(stdout, "==>[recieved kap2_2 response %d] len = %d\n",\
                            kp2_cnt, length);
                    fflush(stdout);
                    print_as_hex(pkt_data, length);
                    memcpy(ka2_key, pkt_data+16, 4);
                    kp2_cnt++;
                    break;
                } else {
                    fprintf(stdout, "==>[recieved kap2_2 response %d] unexpected\n", kp2_cnt);
                }
            }
        }
        
        retry_cnt = 1;
        while (1)
        {
            length = make_keep_alive2_pkt1(pkt_data, kp2_cnt, ka2_key, 3, ka2_is_first);
            sendto(client_sockfd, pkt_data, length, 0,\
                (struct sockaddr *) &remote_addr, sizeof(remote_addr));
            fprintf(stdout, "<==[sended kap2_3 request %d] len = %d\n",\
                    kp2_cnt, length);
            fflush(stdout);
            print_as_hex(pkt_data, length);

            if (retry_cnt > 5)
            {
                goto HEART_BEAT_START;
            }
            memset(pkt_data, 0x00, 1024);
            if ((length = recvfrom(client_sockfd, pkt_data, 1024, 0,\
                (struct sockaddr *) &remote_addr, &sin_size)) == -1)
            {
                fprintf(stdout, "recv kap2_3 timeout, retry %d!\n", retry_cnt++);
                fflush(stdout);
            }
            else
            {
                if (pkt_data[0] == 0x07)
                {
                    fprintf(stdout, "==>[recieved kap2_3 response %d] len = %d\n",\
                            kp2_cnt, length);
                    fflush(stdout);
                    print_as_hex(pkt_data, length);
                    memcpy(ka2_key, pkt_data+16, 4);
                    kp2_cnt++;
                    break;
                } else {
                    fprintf(stdout, "==>[recieved kap2_3 response %d] unexpected\n", kp2_cnt);
                }
            }
        }
        

        while (1)
        {

            length = make_keep_alive2_pkt1(pkt_data, kp2_cnt, ka2_key, 1, ka2_is_first);
            sendto(client_sockfd, pkt_data, length, 0,\
                (struct sockaddr *) &remote_addr, sizeof(remote_addr));
            fprintf(stdout, "<==[sended kap2_loop request %d] len = %d\n", \
                    kp2_cnt, length);
            fflush(stdout);
            print_as_hex(pkt_data, length);

            memset(pkt_data, 0x00, 1024);
            if ((length = recvfrom(client_sockfd, pkt_data, 1024, 0,\
                (struct sockaddr *) &remote_addr, &sin_size)) == -1)
            {
                fprintf(stdout, "recv kap2_loop timeout, retry %d!\n", retry_cnt++);
                fflush(stdout);
                continue;
            } else {
                fprintf(stdout, "==>[recieved kap2_3 response %d] len = %d\n",\
                    kp2_cnt, length);
                fflush(stdout);
                print_as_hex(pkt_data, length);
                memcpy(ka2_key, pkt_data+16, 4);
                kp2_cnt++;
            }
LOOP_RETRY:
            length = make_keep_alive2_pkt1(pkt_data, kp2_cnt, ka2_key, 3, ka2_is_first);
            sendto(client_sockfd, pkt_data, length, 0,\
                (struct sockaddr *) &remote_addr, sizeof(remote_addr));
            fprintf(stdout, "<==[sended kap2_loop request %d] len = %d\n", \
                    kp2_cnt, length);
            fflush(stdout);
            print_as_hex(pkt_data, length);

            memset(pkt_data, 0x00, 1024);
            if ((length = recvfrom(client_sockfd, pkt_data, 1024, 0,\
                (struct sockaddr *) &remote_addr, &sin_size)) == -1)
            {
                fprintf(stdout, "recv kap2_loop timeout, retry %d!\n", retry_cnt++);
                fflush(stdout);
                goto LOOP_RETRY;
            } else {
                fprintf(stdout, "==>[recieved kap2_3 response %d] len = %d\n",\
                    kp2_cnt, length);
                fflush(stdout);
                print_as_hex(pkt_data, length);
                memcpy(ka2_key, pkt_data+16, 4);
                kp2_cnt++;
            }

            sleep(10);
        }
    }
#ifdef WIN32
    closesocket(client_sockfd);
    WSACleanup();
#else

    close(client_sockfd);
#endif
    return 0;
}

static void print_as_hex(uint8_t *buf, int len)
{
    int i;
    for (i=0; i<len; i++)
    {
        if (i%16 == 0 && i!=0)
            fprintf(stdout, "\n");
        fprintf(stdout, "%02x ", *(buf+i));
    }
    fprintf(stdout, "\n\n");
    fflush(stdout);
}

static void gen_ka1_checksum(uint8_t *checksum, uint8_t *seed, uint8_t mode)
{
    uint8_t checksum_t[32] = {0};
    int32_t temp_num;

    switch (mode)
    {
        case 0:
            temp_num = 20000711;
            memcpy(checksum, (uint8_t *)&temp_num, 4);
            temp_num = 126;
            memcpy(checksum+4, (uint8_t *)&temp_num, 4);
            break;
        case 1:
            //md5
            _MD5(seed, 4, checksum_t);
            checksum[0] = checksum_t[2];
            checksum[1] = checksum_t[3];
            checksum[2] = checksum_t[8];
            checksum[3] = checksum_t[9];
            checksum[4] = checksum_t[5];
            checksum[5] = checksum_t[6];
            checksum[6] = checksum_t[13];
            checksum[7] = checksum_t[14];
            break;
        case 2:
            //md4
            _MD4(seed, 4, checksum_t);
            checksum[0] = checksum_t[1];
            checksum[1] = checksum_t[2];
            checksum[2] = checksum_t[8];
            checksum[3] = checksum_t[9];
            checksum[4] = checksum_t[4];
            checksum[5] = checksum_t[5];
            checksum[6] = checksum_t[11];
            checksum[7] = checksum_t[12];
            break;
        case 3:
            //sha1
            _SHA1(seed, 4, checksum_t);
            checksum[0] = checksum_t[2];
            checksum[1] = checksum_t[3];
            checksum[2] = checksum_t[9];
            checksum[3] = checksum_t[10];
            checksum[4] = checksum_t[5];
            checksum[5] = checksum_t[6];
            checksum[6] = checksum_t[15];
            checksum[7] = checksum_t[16];
            break;
        default:
            break;
    }
}


int make_keep_alive2_pkt1(uint8_t *buf, uint8_t cnt, uint8_t *seed, uint8_t type, int is_first)
{
    int index = 0;
    *(buf + index++) = 0x07;
    *(buf + index++) = cnt;
    *(buf + index++) = 0x28; // length
    memcpy(buf+index, "\x00\x0b", 2);
    index += 2;
    buf[index++] = type;
    
    if (is_first) {
        buf[index++] = 0x0f;
        buf[index++] = 0x27;
    } else {
        buf[index++] = 0xdc;        // keep_alive2_flag
        buf[index++] = 0x02;
    }

    buf[index++] = 0x2f;
    buf[index++] = 0x12;

    memset(buf+index, 0, 6);
    index += 6;

    memcpy(buf+index, seed, 4);      // tail
    index += 4;

    if (type == 3) {
        gen_ka1_checksum(buf+index, seed, seed[0] & 0x03);
        index += 8;
        memset(buf+index, 0 , 4);   // host_ip
        index += 4;
        memset(buf+index, 0 , 8);   // host_ip
        index += 8;
    } else {
        memset(buf+index, 0, 20);
        index += 20;
    }

    return index;
}
