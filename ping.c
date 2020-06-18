/*****************************************************************
//
//  NAME:        Christopher Na
//  Programming Assignment, simulate basic server and client sending messages
//
****************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/ip_icmp.h>
#include "checksum.h"

#define PACKETS  5 // amount of packets to send

#define WAIT   6 // max wait time before alarm

#define PACKET_SIZE 4096 // max packet size

#define HEADER_SIZE 8 // icmp header size
 
// global variables

int nsend = 0;          // track packets sent
int nreceived = 0;      // track packets recieved
double total = 0;       // track total packets for statistics

struct timeval tvrecv;  // track timeofday on send
struct timeval tvsend;  // track timeofday on recieve 

pid_t pid;              // identifier for icmp packet

// functions

void calculate(struct timeval *out, struct timeval *in);
void send_ping(int *sock, struct sockaddr_in *dest);
void recv_packet(int *sock);
void stats(char *name);
int unpack_packet(char *buf, int len, struct sockaddr_in *from);
int pack_packet(char *sendpacket);

/*****************************************************************
//
//  Function name: main
//
//  DESCRIPTION:   Driver code
//
//  Parameters:    count (int) : contains the number of arguments
//                               which will be processed
//
//  Return values:  none
//
****************************************************************/
int main(int argc, char *argv[]) {
    
    // declare variables, finding DNS

    struct addrinfo hints, *result;
    int ipstr;
    char *name = argv[1];
    struct sockaddr_in *dest;

    // declare variables for sockets

    int sock;
    int opt = 65507;

    // check arguments entered

    if (argc != 2) 
    {
        printf("usage: ./ping [domain]\n");
        return -1;
    }

    // check for root access

    if (getuid() != 0) 
    {
        printf("No Root Privliges\n");
        return -1;
    }
        
    // zero out hints & IPV4

    memset(&hints,0,sizeof(struct addrinfo)); 
    hints.ai_family = AF_INET; 

    // Convert name to ip

    if ((ipstr = getaddrinfo(argv[1], NULL, &hints, &result)) != 0){
        printf("Domain not found\n");
        return -1;
    }

    // inet socket address

    dest = (struct sockaddr_in *) result->ai_addr;

    // create a socket

    if( (sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) 
    {
        perror("Socket");
        return -1;
    }
    
    // set recieve buffer size

    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt));

    // get pid to identify packets and will be used for the id field in the icmp packet
    // allows for more than one ping program to run on same host

    pid = getpid();
    
    printf("PING %s \n", name);
   
    // start sending packets

    send_ping(&sock, dest); 

    // print statistics after sending packets

    stats(name);

    //free the addrinfo struct

    freeaddrinfo(result);

    close(sock);

    return 0;
}

/*****************************************************************
//
//  Function name: send_ping
//
//  DESCRIPTION:   send the icmp packet over the socket
//
//  Parameters:    sock (int): file descriptor for raw socket,  
//                  dest: (struct) addr_info of who to ping
//
//  Return values:  none
//
****************************************************************/

void send_ping(int *sock, struct sockaddr_in *dest)
{
    int packetsize;
    char sendpacket[PACKET_SIZE];
    int socket = *sock;
    struct sockaddr_in destination = *dest;

    while (nsend < PACKETS)
    {   
        nsend++; 
        
        packetsize = pack_packet(sendpacket);  

        // BSD system call timeofday gets the time when the packet is first sent

        gettimeofday(&tvsend, NULL); 

        //send the datagram

        if (sendto(socket, sendpacket, packetsize, 0, (struct sockaddr *) &destination, sizeof(destination)) < 0)
        {
            perror("sendto error");
            exit(-1);
        }     
        
        recv_packet(sock);
    }
}

/*****************************************************************
//
//  Function name: pack_packet
//
//  DESCRIPTION:   Fill the icmp echo request to send over socket. Ip header is filled when sent.
//
//  Parameters:    sendpacket (char): the packet to send
//
//  Return values:  packsize: total size of packet
//
****************************************************************/

int pack_packet(char *sendpacket)
{
    int packsize;

    //default area after icmp header
    
    int datalen = 20;
    struct icmp *icp;

    icp = (struct icmp*)sendpacket;
    icp->icmp_type = ICMP_ECHO;
    icp->icmp_code = 0;
    icp->icmp_cksum = 0;

    // set big endian for sequence

    icp->icmp_seq = htons(nsend);
    icp->icmp_id = pid;

    packsize = HEADER_SIZE + datalen;

    // compute checksum after filling in

    icp->icmp_cksum = checksum((unsigned short*)icp, packsize);                 

    return packsize;
}

/*****************************************************************
//
//  Function name: recv_packet
//
//  DESCRIPTION:  handle the packet in the receive buffer 
//
//  Parameters:    sock (int): file desciptor for raw socket
//
//  Return values:  none
//
****************************************************************/

void recv_packet(int *sock)
{
    int get; 
    char recvpacket[PACKET_SIZE];
    struct sockaddr_in from;
    socklen_t fromlen;
    fromlen = sizeof(from);
    int socket = *sock;

    while (nreceived < nsend)
    {
        nreceived++;

        // warn user for no response seen indicating dropped packet

        alarm(WAIT);

        if ((get = recvfrom(socket, recvpacket, sizeof(recvpacket), 0, (struct sockaddr*) &from, &fromlen)) < 0)
        {
            perror("recvfrom error");
            exit(-1);
        } 

        // open packet and check if it is valid

        if (unpack_packet(recvpacket, get, &from) == 2)
        {
            continue;
        } 
    
    }
}

/*****************************************************************
//
//  Function name: unpack_packet
//
//  DESCRIPTION:   read the icmp packet
//
//  Parameters:    buf (char): size of buffer, len (int): bytes received of packet, 
//                  from (struct): address of the sender
//
//  Return values:  2: echo reply packet
//                  -1: invalid packet
//                  0: non-echo packet
//
****************************************************************/

int unpack_packet(char *buf, int len, struct sockaddr_in *from)
{
    int iphdrlen;
    struct ip *ip;
    struct icmp *icp;
    struct sockaddr_in in = *from;
    double rtt;

    ip = (struct ip*)buf;
    
    // look at ip header and check to see if it has at least 8 bytes
    // convert bit words to bytes

    iphdrlen = ip->ip_hl << 2; 
    icp = (struct icmp*)(buf + iphdrlen);
    len -= iphdrlen; 

    if (len < 8)   
    {
        printf("ICMP length is invalid\n");
        return  -1;
    }

    // check each packet to see if it came from the host as the socket accepts all incoming ICMP packets
    // if not ignore the packet

    if ((icp->icmp_type == ICMP_ECHOREPLY) && (icp->icmp_id == pid))
    {  

        // get the time when packet was recieved succesfully    
    
        gettimeofday(&tvrecv, NULL); 
    
        // time start - time end to calculate rtt

        calculate(&tvrecv, &tvsend); 

        rtt = 1000000.0 * tvrecv.tv_sec  + tvrecv.tv_usec / 1000.0 ;         
     
        printf("%d bytes from %s: icmp_seq=%u ttl=%d time=%.2f ms\n", len, inet_ntoa(in.sin_addr), htons(icp->icmp_seq), ip->ip_ttl, rtt);

        // add onto the rtt average

        total += rtt;
        
        return 2;
    }
    
    else
    {
        return 0;
    }
}

/*****************************************************************
//
//  Function name: calculate
//
//  DESCRIPTION:   calculate the out = out - in of the timeval
//  
//  Parameters:    out (struct): timeofday on send, in (struct): timeofday on recv
//
//  Return values: none 
//
****************************************************************/

void calculate(struct timeval *out, struct timeval *in)
{
    // subtract seconds
    tvrecv.tv_sec = out->tv_sec - in->tv_sec;
    // subtract microseconds
    tvrecv.tv_usec = out->tv_usec - in->tv_usec;   

    // if microsecond is negative subtract one second and add 1000000 microseconds
    while (tvrecv.tv_usec < 0) {
        tvrecv.tv_usec += 1000000;
        tvrecv.tv_sec--;
    }
}

/*****************************************************************
//
//  Function name: stats
//
//  DESCRIPTION:   print out the statistics of all 5 packets
//
//  Parameters:    name (char): hostname
//
//  Return values: none  
//
****************************************************************/

void stats(char *name)
{
    printf("--------------------%s statistics-------------------\n", name);
    printf("%d packets transmitted, %d received , %d lost\n", nsend, nreceived, (nsend - nreceived) / nsend * 100);
    printf("rtt average %.2f ms \n", (total / 5));
    exit(-1);
} 
