#ifndef _OPOZNIENIA_H_
#define _OPOZNIENIA_H_

// This is a header used for storing many defines and some variables
// for opoznienia.c.
/*#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/util.h>*/
#include <pwd.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h> 
#include <sys/time.h>
#include <inttypes.h>
#include <fcntl.h>
// this sets ICMP declaration
#include <netinet/ip_icmp.h>
// Getifaddr
#include <ifaddrs.h>

#include "err.h"

#include "mdnscache.h"

#define QUEUE_LENGTH 16
#define MAX_LINE 16384
#define LINE_SIZE 100
#define MAX_UINT16_T 65535
// For communication (udp)
#define SEND_SIZE 1
#define RETURN_SIZE 2
#define RECIEVED_SIZE 1
#define SEND_SIZE_2 2
// Max latency in ms.
#define MAX_LATENCY 10000
#define POLL_WAIT 100

#define ICMP_HEADER_LEN 8
#define NOBODY_UID_GID 99
#define BSIZE 1000

// MDNS PORT, SHOULD NOT BE CHANGED!
in_port_t MDNS_PORT = 5353;

// Used to put binary data (bytes, shorts and ints) into an array.
#define util_put8(buf, data) ((*(buf) = (unsigned char)(data)&0xff),1)
#define util_put16(buf, data) ( \
        (*(buf) = (unsigned char)((data)>>8)&0xff), \
        (*((buf)+1) = (unsigned char)(data)&0xff),  \
        2)
#define util_put32(buf, data) ( \
        (*((buf)) = (unsigned char)((data)>>24)&0xff), \
        (*((buf)+1) = (unsigned char)((data)>>16)&0xff), \
        (*((buf)+2) = (unsigned char)((data)>>8)&0xff), \
        (*((buf)+3) = (unsigned char)(data)&0xff), \
        4)
#define util_get8(buf) ((*(buf))&0xff)
#define util_get16(buf) ((((*(buf))<<8)&0xff00) + ((*((buf)+1)) & 0xff))
#define util_get32(buf) ((((*(buf))<<24)&0xff000000) + \
        (((*((buf)+1))<<16)&0x00ff0000) + \
        (((*((buf)+2))<< 8)&0x0000ff00) + \
        (((*((buf)+3)    )&0x000000ff)))


#define RRTYPE_A 1
#define RRTYPE_PTR 12
#define RRTYPE_AAAA 28
#define RRTYPE_ALL 255

#define MDNS_TTL 255
#define INTERNET_CLASS 0x0001

// wlan0 or eth0
#define INTERNET_INTERFACE_WLAN "wlan0"
#define INTERNET_INTERFACE_ETH "eth0"

// PORTS
int32_t UDP_PORT_NUM = 3382;
int32_t TELNET_PORT_NUM = 3637;

// We will make more random this name.
const char* BASE_NAME = "franek.\0";

char* COMPUTER_NAME;

// Beginning name udp
const char* DEFAULT_DOMAIN_UDP = "franek._opoznienia._udp.local\0";
const char* DEFAULT_DOMAIN_TCP = "franek._opoznienia._ssh._tcp.local\0";

const char* SERVICE_NAME_UDP = "_opoznienia._udp.local\0";
const char* SERVICE_NAME_TCP = "_opoznienia._ssh._tcp.local\0";

// NOT USING TCP ON DEFAULT.
int32_t USE_TCP = 0;

// OUR DOMAIN NAME
char* MDNS_DOMAIN_UDP;
char* MDNS_DOMAIN_TCP;

// OUR IP
unsigned char* MDNS_IP;

// HOW FAST WE ASK ABOUT OTHER DEVICES IN SECONDS
int MDNS_UPDATE_RATE = 10; // Well float doesn't work on sleep...
// HOW MANY TIMES WE UPDATE THE LATENCIES IN SECONDS
float MDNS_LATENCY_RATE = 1.0f;


const char* MDNS_ADDRESS = "224.0.0.251";

struct sockaddr_in multicast_addr;


unsigned short
in_cksum(unsigned short *addr, int len)
{
    int             nleft = len;
    int             sum = 0;
    unsigned short  *w = addr;
    unsigned short  answer = 0;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

        /* 4mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w ;
        sum += answer;
    }

        /* 4add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);         /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return(answer);
}

void drop_to_nobody() {
  
  struct passwd * nobody_passwd;

  nobody_passwd = getpwnam("nobody");
  if (nobody_passwd  == NULL) 
    syserr("getpwnam");
  
  if (setgid(nobody_passwd -> pw_gid) != 0)
    syserr("setgid");
  if (setuid(nobody_passwd -> pw_uid) != 0)
    syserr("setuid");
  
   if (setuid(0) != -1)
     syserr("ERROR: Managed to regain root privileges?");

}


/*void* memdup(const void* d, size_t s) { 
   void* p; 
   return ((p = malloc(s))?memcpy(p, d, s):NULL);
}*/

void* memdup(const void *data, size_t size)
{
    void *m = malloc(size);

    if (m == NULL)
    {
        return NULL;
    }
    memcpy(m, data, size);
    return m;
}


typedef struct _List
{
    void* data;
    struct _List* next;

} List;


// Inits an empty list. O(1)
int initList (List* list)
{
    list = NULL;
    return 0;
}

// Inserts pointer to data at the end. O(n)
List* insertList (List* list, void* data)
{
    if (list == NULL)
    {
        list = malloc(sizeof(List));
        if (list == NULL)
            syserr("Malloc has failed you\n");
        list->data = data;
        list->next = NULL;
        return list;
    }
    else
    {
        List* cur;
        cur = list;
        while (cur->next != NULL)
            cur = cur->next;
        List* added = malloc(sizeof(List));
        if (added == NULL)
            syserr("Malloc has failed you\n");
        added->data = data;
        added->next = NULL;
        cur->next = added;
        return list;
    }
    return NULL;
}

// Removes data from list. (looking by pointer) and returns pointer to that data
// O(n)
void* removeList (List* list, void* data)
{
    List* cur = list;
    // Check first?
    if (cur != NULL)
    {
        if (cur->data == data)
        {
            void* res;
            res = list->data;
            List* next = list->next;
            free(list);
            list = next;
            return res;
        }
    }
    // Check all the rest.
    if (cur != NULL)
    {
        while (cur->next != NULL)
        {
            if (cur->next->data == data)
            {
                void* res;
                res = cur->next->data;
                List* next = cur->next->next;
                free(cur->next);
                cur->next = next;
                return res;
            }
            cur = cur->next;
        }
    }
    return NULL;
}

void clearList (List* list)
{
    while (list != NULL)
    {
        List* next = list->next;
        free(list);
        list = next;
    }
}

void setBit16(uint16_t* number, int position)
{
    *number |= 1 << position;
}

void setBit32(uint32_t* number, int position)
{
    *number |= 1 << position;
}

void clearBit16(uint16_t* number, int position)
{
    *number &= ~(1 << position);
}

void clearBit32(uint32_t* number, int position)
{
    *number &= ~(1 << position);
}


int checkBit16(uint16_t* number, int position)
{
    return (*number >> position) & 1;
}

int checkBit32(uint32_t* number, int position)
{
    return (*number >> position) & 1;
}
// Structures used in mDNS packet.

// This is the A type of RDData - IP Address.
typedef unsigned char mDNS_A_Data;
// This is the PTR type of RDData - host name that represents
// the supplied IP address (PTR)
typedef char* mDNS_PTR_Data;

// Standard mdns header.
typedef struct _mDNSHeader 
{
    uint16_t id;
    uint16_t flags;
    uint16_t num_of_questions;
    uint16_t num_of_answers;
    uint16_t authority_num;
    uint16_t additional_num;

} mDNSHeader;

// Question sent in mdns packet.
typedef struct _mDNSQuestion
{
    // The domain name being queried.
     char* qname;
    // The resource records being requested.
    uint16_t qtype;
    // The Resource Record(s) class being requested e.g. internet, chaos etc.
    uint16_t qclass;

} mDNSQuestion;

// mDNS answer. Also Domain authority and additional information has
// exactly the same structure.
typedef struct _mDNSResourceRecord
{
    // The name being returned.
    char* qname;
    // The RR type, for example SOA or AAAA.
    uint16_t qtype;
    // The RR class, for instance, Internet, Chaos etc.
    uint16_t qclass;
    // The time in seconds that the record may be cached. 
    // 0 indicates the record should not be cached.
    uint32_t ttl;
    // Defines the length in bytes (octets) of the RDATA record.
    uint16_t rdLength;
    // Each (or rather most) resource record types have a specific RDATA 
    // format which reflect their resource record format.
    void* rdData;

} mDNSResourceRecord;

// The whole mDNS packet structure.
typedef struct _mDNSPacket
{
    mDNSHeader* header;
    List* questions;
    List* answers;
    List* authority;
    List* additional;
} mDNSPacket;

// Returns random id for legacy purpose only.
uint16_t getRandomLegacyID()
{
    int forgenerator = time(NULL);
    srand(forgenerator);
    return (uint16_t) (rand() % MAX_UINT16_T);
}

int free_mDNSHeader (mDNSHeader* mdns)
{
    if (mdns != NULL)
        free(mdns);
    return 0;
}


mDNSHeader* create_new_mDNSHeader (uint16_t legacyR, int isResponse, 
    int isAuthority, int isTruncated, uint16_t howManyQuestions, 
    uint16_t howManyAnswers)
{
    mDNSHeader* mdns = malloc(sizeof(mDNSHeader));
    if (mdns == NULL)
        syserr("malloc has failed you\n");
    // Init
    mdns->id = 0;
    mdns->flags = 0;
    mdns->num_of_questions = 0;
    mdns->num_of_answers = 0;
    mdns->authority_num = 0;
    mdns->additional_num = 0;
    // According to RFC must be 0
    if (legacyR == 0)
        mdns->id = 0;
    // or we are using legacy unicast
    else
        mdns->id = legacyR;
    // If response bit QR = 1, question bit QR = 0
    if (isResponse == 1)
        setBit16(&(mdns->flags), 15);
    else
        clearBit16(&(mdns->flags), 15);
    // Now set the OPCODE bits, always 0.
    clearBit16(&(mdns->flags), 14);
    clearBit16(&(mdns->flags), 13);
    clearBit16(&(mdns->flags), 12);
    clearBit16(&(mdns->flags), 11);
    // Now AA bit, almost always 0
    if (isAuthority == 1)
        setBit16(&(mdns->flags), 10);
    else
        clearBit16(&(mdns->flags), 10);
    // TC bit, almost always should be 0
    if (isTruncated == 1)
        setBit16(&(mdns->flags), 9);
    else
        clearBit16(&(mdns->flags), 9);
    // RC bit must be 0, and must be ignored.
    clearBit16(&(mdns->flags), 8);
    // RA bit must be 0, and must be ignored.
    clearBit16(&(mdns->flags),7);
    // Zero bit must be zero XD
    clearBit16(&(mdns->flags), 6);
    clearBit16(&(mdns->flags), 5);
    clearBit16(&(mdns->flags), 4);
    // All other must also be zeroes.
    clearBit16(&(mdns->flags), 3);
    clearBit16(&(mdns->flags), 2);
    clearBit16(&(mdns->flags), 1);
    clearBit16(&(mdns->flags), 0);
    mdns->num_of_questions = howManyQuestions;
    mdns->num_of_answers = howManyAnswers;
    mdns->authority_num = 0;
    mdns->additional_num = 0;
    return mdns;
}


int free_mDNSQuestion (mDNSQuestion* query)
{
    if (query != NULL)
    {
        if (query->qname != NULL)
            free(query->qname);
        free(query);
    }
    return 0;
}

int free_mDNSQuestions (List* list)
{
    List* cur = list;
    while(cur != NULL)
    {
        List* next = cur->next;
        free_mDNSQuestion(cur->data);
        free(cur);
        cur = next;
    }
    return 0;
}


// The name should be represented in a format that will be sent in packet :
// length string, length string, etc.. should be null terminated...
// qtype: A-1 PTR-12, TXT-16
mDNSQuestion* create_new_mDNSQuestion (const char* name, uint16_t qtype)
{
    mDNSQuestion* query = malloc(sizeof(mDNSQuestion));
    if (query == NULL)
        syserr("Malloc has failed you\n");
    // name like _opoznienia._upd_.local. and now copy the string
    query->qname = malloc((strlen(name) + 1) * sizeof(unsigned char));
    if (query->qname == NULL)
        syserr("Malloc has failed you\n");
    int i = 0;
    while (name[i] != '\0')
    {
        query->qname[i] = name[i];
        i++;
    }
    query->qname[i] = '\0';
    // If PTR or A
    query->qtype = qtype;
    // Internet
    query->qclass = INTERNET_CLASS;
    return query;
}

int free_mDNSResourceRecord (mDNSResourceRecord* rr)
{
    if (rr != NULL)
    {
        if (rr->qname != NULL)
            free(rr->qname);
        if (rr->rdData != NULL)
            free(rr->rdData);
        free(rr); 
    }
    return 0;
}

int free_mDNSResourceRecords (List* list)
{
    List* cur = list;
    List* next = NULL;
    while(cur != NULL)
    {
        next = cur->next;
        free_mDNSResourceRecord(cur->data);
        free(cur);
        cur = next;
    }
    return 0;
}

// The name should be represented in a format that will be sent in packet :
// length string, length string, etc.. should be null terminated...
// qtype: A-1 PTR-12, TXT-16 etc..
// The rdData pointer should be allocated earlier and will be freed when
// mDNSResourceRecord will be freed.
mDNSResourceRecord* create_new_mDNS_answer (const char* name, uint16_t qtype, 
    uint16_t rdLength, void* rdData)
{
    mDNSResourceRecord* answer = malloc(sizeof(mDNSResourceRecord));
    if (answer == NULL)
        syserr("Malloc has failed you\n");
    answer->qname = malloc((strlen(name) + 1) * sizeof(unsigned char));
    if (answer->qname == NULL)
        syserr("Malloc has failed you\n");
    int i = 0;
    while (name[i] != '\0')
    {
        answer->qname[i] = name[i];
        i++;
    }
    answer->qname[i] = '\0';
    answer->qtype = qtype;
    answer->qclass = INTERNET_CLASS;
    answer->ttl = MDNS_TTL;
    answer->rdLength = rdLength;
    if (answer->qtype == RRTYPE_A)
    {
        // Ok now we set the address in rdData
        // Which is xxx.xxx.xxx.xxx (4 bytes)
        answer->rdData = rdData;
    }
    /*else if (answer->qtype == RRTYPE_AAAA)
    {
        // at this time we wont handle this.
    }*/
    else if (answer->qtype == RRTYPE_PTR)
    {
        // Insert the unsigned char* name
        answer->rdData = rdData;
    }
    // ignoring else should return a null
    else
    {

        free(answer->qname);
        free(answer);
        return NULL;
    }
    return answer;
}

int free_mDNSPacket(mDNSPacket* packet)
{
    if (packet != NULL)
    {
        free_mDNSHeader(packet->header);
        free_mDNSQuestions(packet->questions);
        free_mDNSResourceRecords(packet->answers);
        //free_mDNSResourceRecords(packet->authority); this will be NULL
        //free_mDNSResourceRecords(packet->additional); this will be NULL
        free(packet);
    }
    return 0;
}

// Duplicating DNS structures.

/*static mDNSQuestion* mdns_copy_question(const mDNSQuestion* q)
{
    mDNSQuestion* res;

    if (q == NULL)
        return NULL;

    res = malloc(sizeof(mDNSQuestion));
    res->qname = strdup(q->qname);
    res->qtype = q->qtype;
    res->qclass = q->qclass;

    return res;
}*/

/*static List* mdns_copy_questions(List* qs)
{
    List* res = NULL;
    List* cur;
    mDNSQuestion* added;

    for (cur = qs; cur != NULL; cur = cur->next)
    {
        added = mdns_copy_question(cur->data);
        res = insertList(res, added);
    }

    return res;
}*/

void* mdns_copy_resource_record_rdData(uint16_t qtype, const void* rdData, 
    int32_t rdLength)
{
    void* res = NULL;

    if (rdData == NULL)
        return NULL;

    if (qtype == RRTYPE_A)
    {
        //res = memdup(&rdData, rdLength);
        res = malloc(4);
        res = memcpy(res, rdData, rdLength);
    }
    else if (qtype == RRTYPE_PTR)
    {
        res = strdup(rdData);
    }

    return res;
}

mDNSResourceRecord* mdns_copy_resource_record (const mDNSResourceRecord* rr)
{
    mDNSResourceRecord* res;

    if (rr == NULL)
        return NULL;

    res = malloc(sizeof(mDNSResourceRecord));
    if (res == NULL)
        syserr("Malloc has failed you");
    res->qname = strdup(rr->qname);
    res->qtype = rr->qtype;
    res->qclass = rr->qclass;
    res->ttl = rr->ttl;
    res->rdLength = rr->rdLength;
    res->rdData = mdns_copy_resource_record_rdData(rr->qtype, rr->rdData, 
        rr->rdLength);

    return res;
}


/*static List* mdns_copy_resource_records(List* rrs)
{
    List* res = NULL;
    List* cur;
    mDNSResourceRecord* added;

    for (cur = rrs; cur != NULL; cur = cur->next)
    {
        added = mdns_copy_resource_record(cur->data);
        res = insertList(res, added);
    }

    return res;
}

static mDNSPacket* mdns_copy_packet(const mDNSPacket* mdns)
{
    mDNSPacket* res;

    if (mdns == NULL)
        return NULL;

    res = malloc(sizeof(mDNSPacket));
    if (res == NULL)
        syserr("Malloc has failed you");

    res->header = malloc(sizeof(mDNSHeader));
    if (res->header == NULL)
        syserr("Malloc has failed you");
    res->header->id = mdns->header->id;
    res->header->flags = mdns->header->flags;
    res->header->num_of_questions = mdns->header->num_of_questions;
    res->header->num_of_answers = mdns->header->num_of_answers;
    res->header->authority_num = mdns->header->authority_num;
    res->header->additional_num = mdns->header->additional_num;

    return res;
}*/

int32_t mdns_init() {
 
    /*srand(time(NULL));
 
    int len = strlen(name_base);
    name = malloc(sizeof(unsigned char) * len + sizeof(unsigned char) * 5);
    update_name();*/
 
    char *multicast_dotted_address = "224.0.0.251";
    in_port_t port = (in_port_t) MDNS_PORT;
 
    struct sockaddr_in local_address;
    
    struct ip_mreq ip_mreq;
    int sock;
    //int multiaddr_len;
 
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        syserr("socket");
 
    ip_mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (inet_aton(multicast_dotted_address, &ip_mreq.imr_multiaddr) == 0)
        syserr("inet_aton");
 

    uint32_t ttl = MDNS_TTL;
    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, 
        sizeof(uint32_t)) == -1)
    {
        syserr("mDNS error calling setsockopt for IP_MULTICAST_TTL\n");
        close(sock);
    }
    int optval = 1;
    if(0 != setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void*) &optval, 
        sizeof(optval)))
    {
        syserr("Unable to allow address reuse on the MDNS socket");
    }
 
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void*)&ip_mreq, 
        sizeof ip_mreq) < 0)
    {
        syserr("setsockopt");
    }

    optval = 0;
    if (setsockopt(sock, SOL_IP, IP_MULTICAST_LOOP, (void*)&optval, 
        sizeof optval) < 0)
    {
        syserr("setsockopt loop");
    }
 
    local_address.sin_family = AF_INET;
    local_address.sin_addr.s_addr = htonl(INADDR_ANY);
    local_address.sin_port = htons(port);
 
    if (bind(sock, (struct sockaddr *)&local_address, sizeof local_address) < 0)
        syserr("bind");
 
    struct addrinfo addr_hints;
    struct addrinfo *addr_result;
 
    (void) memset(&addr_hints, 0, sizeof(struct addrinfo));
    addr_hints.ai_family = AF_INET;
    addr_hints.ai_socktype = SOCK_DGRAM;
    addr_hints.ai_protocol = IPPROTO_UDP;
    addr_hints.ai_flags = 0;
    addr_hints.ai_addrlen = 0;
    addr_hints.ai_addr = NULL;
    addr_hints.ai_canonname = NULL;
    addr_hints.ai_next = NULL;
 
    char port_str[10];
    sprintf(port_str, "%d", MDNS_PORT);
 
    int err;
    if(0 != (err = getaddrinfo(multicast_dotted_address, port_str, &addr_hints, 
        &addr_result)))
    {
        syserr("UDP: getaddrinfo\n");
    }
 
    multicast_addr.sin_family = AF_INET;
    multicast_addr.sin_addr.s_addr =
        ((struct sockaddr_in*) (addr_result->ai_addr))->sin_addr.s_addr;
    multicast_addr.sin_port = htons((uint16_t) MDNS_PORT);
    //multiaddr_len = sizeof(multicast_addr);
 
    freeaddrinfo(addr_result);
    //init_mdns_domain();
    return sock;
 
}


// Function for multicasting raw data over sock.

static int32_t mdns_send_raw(int32_t sock, uint32_t datalen, 
    unsigned char* data)
{
    //struct sockaddr_in addr;
    int32_t n;

    /*addr.sin_family = AF_INET;
    addr.sin_port = htons(MDNS_PORT);
    addr.sin_addr.s_addr = inet_addr("224.0.0.251");
    */

    n = sendto(sock, data, datalen, 0, (struct sockaddr*)&multicast_addr, 
        sizeof(struct sockaddr_in));
    if (n == -1)
        syserr("Error sending packet\n");
    else if (n != datalen)
    {
        syserr("Sent only %d of %d bytes of data", n, datalen);
    }
    return 0;
}


// Functions for sending mDNS packets

static int32_t mdns_getlength_name (const void* name)
{
    return strlen((const char*)name) + 2;
}

static int32_t mdns_getlength_question (const mDNSQuestion* q)
{
    return mdns_getlength_name(q->qname) + 4;
}

static int32_t mdns_getlength_questions (const List* qs)
{
    int32_t length = 0;
    List* current;
    for (current = (List*)qs; current != NULL; current = current->next)
        length += mdns_getlength_question(current->data);
    return length;
}

static int32_t mdns_getlength_resource_record_rddata (uint16_t qtype, 
    const void* rdData)
{
    int32_t rdlength = 0;

    if (qtype == RRTYPE_A)
    {
        // Because xxx.xxx.xxx.xxx
        rdlength = 4;
    }
    else if (qtype == RRTYPE_PTR)
    {
        // Because it's a string.
        rdlength = mdns_getlength_name(rdData);
    }
    return rdlength;
}

static int32_t mdns_getlength_resource_record (const mDNSResourceRecord* rr)
{
    int32_t rdlength = mdns_getlength_resource_record_rddata(rr->qtype, 
        rr->rdData);
    if ((rdlength == 0) && (rr->rdData != NULL))
        rdlength = rr->rdLength;
    return (mdns_getlength_name(rr->qname) + 10 + rdlength);
}

static int32_t mdns_getlength_resource_records (const List* rrs)
{
    int32_t length = 0;
    List* cur;

    for (cur = (List*)rrs; cur != NULL; cur = cur->next)
        length += mdns_getlength_resource_record(cur->data);

    return length;
}

static int32_t mdns_getlength_packet (const mDNSPacket* mdns)
{
    int32_t length = 0;

    // Header.
    length += 12;

    // Questions
    length += mdns_getlength_questions(mdns->questions);

    // Resource records
    length += mdns_getlength_resource_records(mdns->answers);
    length += mdns_getlength_resource_records(mdns->authority);
    length += mdns_getlength_resource_records(mdns->additional);

    return length;
}

static int32_t mdns_put_name (unsigned char* data, uint32_t datalen, 
    int32_t offset, const char* qname)
{
    int32_t i = 0;
    unsigned char *b, *c;
    b = (unsigned char *)qname;

    // strchr returns the pointer to first occurence in string.
    while ((c = strchr(b, '.')))
    {
        // Length of domain-name segment
        i += util_put8(&data[offset + i], c - b);
        // Domain-name segment
        memcpy(&data[offset + i], b, c - b);
        // Increment the destination pointer
        i += c - b;
        b = c + 1;
    }
    // Length of domain-name segment
    i += util_put8(&data[offset + i], strlen(b));
    // Domain-name segment
    strcpy(&data[offset + i], b);
    // Increment the destination pointer
    i += strlen(b) + 1;

    return i;
}

static int32_t mdns_put_question (unsigned char* data, uint32_t datalen, 
    int32_t offset, const mDNSQuestion* q)
{
    int32_t i = 0;

    // QNAME
    i += mdns_put_name(data, datalen, offset + i, q->qname);
    // QTYPE
    i += util_put16(&data[offset + i], q->qtype);
    // QCLASS
    i += util_put16(&data[offset + i], q->qclass);

    return i;
}

static int32_t mdns_put_resource_record (unsigned char* data, uint32_t datalen, 
    int32_t offset, const mDNSResourceRecord* rr)
{
    int32_t i = 0;

    i += mdns_put_name(data, datalen, offset + i, rr->qname);
    i += util_put16(&data[offset + i], rr->qtype);
    i += util_put16(&data[offset + i], rr->qclass);
    i += util_put32(&data[offset + i], rr->ttl);
    i += util_put16(&data[offset + i], rr->rdLength);

    if (rr->qtype == RRTYPE_A)
    {
        memcpy(&data[offset + i], rr->rdData, rr->rdLength);
        i += rr->rdLength;
    }
    else if (rr->qtype == RRTYPE_PTR)
    {
        i += mdns_put_name(data, datalen, offset + i, 
            (const unsigned char*)rr->rdData);
    }
    // We don't need other types.
    return i;
}

int32_t mdns_send_packet(int32_t sock, const mDNSPacket* mdns)
{
    int32_t res;
    uint32_t datalen;
    unsigned char* data;
    int32_t offset;
    List* cur;

    // Calculate the length of the buffer we will need to hold the mDNS packet
    datalen = mdns_getlength_packet(mdns);

    // Allocate buffer
    data = (unsigned char*) malloc(datalen);
    if (data == NULL)
        syserr("Malloc has failed you\n");

    // Construct the datagram
    // Header
    offset = 0;
    offset += util_put16(&data[offset], mdns->header->id);
    offset += util_put16(&data[offset], mdns->header->flags);
    offset += util_put16(&data[offset], mdns->header->num_of_questions);
    offset += util_put16(&data[offset], mdns->header->num_of_answers);
    offset += util_put16(&data[offset], mdns->header->authority_num);
    offset += util_put16(&data[offset], mdns->header->additional_num);

    // Questions
    for (cur = mdns->questions; cur != NULL; cur = cur->next)
        offset += mdns_put_question(data, datalen, offset, cur->data);

    // Resource records
    for (cur = mdns->answers; cur != NULL; cur = cur->next)
        offset += mdns_put_resource_record(data, datalen, offset, cur->data);
    for (cur = mdns->authority; cur != NULL; cur = cur->next)
        offset += mdns_put_resource_record(data, datalen, offset, cur->data);
    for (cur = mdns->additional; cur != NULL; cur = cur->next)
        offset += mdns_put_resource_record(data, datalen, offset, cur->data);

    // Send the datagram
    // Offset can be shorter than datalen due to name compression
    res = mdns_send_raw(sock, offset, data);
    free(data);
    return res;
}

// Sends an mdns query.
int32_t mdns_send_query (int32_t sock, const char* domain, uint16_t qtype)
{
    int32_t res;
    mDNSPacket* mdns;
    mDNSQuestion* q;

    if ((domain == NULL) || (strlen(domain) > 255))
    {
        syserr("Wrong domain!");
    }

    mdns = (mDNSPacket*) malloc(sizeof(mDNSPacket));
    if (mdns == NULL)
        syserr("Malloc has failed you");
    mDNSHeader* header;
    // Sending 1 question.
    header = create_new_mDNSHeader(0, 0, 0, 0, 1, 0);

    mdns->header = header;
    // Setting up question.
    q = (mDNSQuestion*) malloc(sizeof(mDNSQuestion));
    if (q == NULL)
        syserr("Malloc has failed you");

    q->qname = strdup(domain);
    q->qtype = qtype;
    q->qclass = 0x0001;
    // Adding to question list
    List* list;
    list = NULL;
    list = insertList(list, (void *) q);
    if (list == NULL)
        syserr("Error empty list");
    mdns->questions = list;
    mdns->answers = NULL;
    mdns->authority = NULL;
    mdns->additional = NULL;
    // Send the packet
    res = mdns_send_packet(sock, mdns);
    // No longer needed, release the kraken!
    free_mDNSPacket(mdns);

    return res;

}

int32_t mdns_send_resource_records (int32_t sock, mDNSResourceRecord* rr)
{
    int32_t res;
    mDNSPacket* mdns;

    if (rr == NULL)
        return -1;

    mdns = (mDNSPacket*) malloc(sizeof(mDNSPacket));
    mdns->header = create_new_mDNSHeader(0, 1, 0, 0, 0, 1);
    mdns->questions = NULL;
    List* list;
    mDNSResourceRecord* copiedrr = mdns_copy_resource_record(rr);
    list = NULL;
    list = insertList(list, (void*) copiedrr);
    if (list == NULL)
        syserr("Error empty list");
    mdns->answers = list;
    mdns->authority = NULL;
    mdns->additional = NULL;

    res = mdns_send_packet(sock, mdns);

    free_mDNSPacket(mdns);

    return res;

}

int32_t mdns_send_A(int32_t sock, const char* name, const unsigned char* ip)
{
    int32_t res;
    mDNSResourceRecord* rr;
    mDNS_A_Data* rdData;
    int32_t i;

    

    if (name == NULL)
        return -1;
    if (strlen(name) > 255)
        return -1;
    if (ip == NULL)
        return -1;


    rdData = malloc(sizeof(uint32_t));
    if (rdData == NULL)
        syserr("Malloc failed");
    for(i = 0; i < 4; i++)
    {
        util_put8(&rdData[i], ip[i]);
    }

    rr = malloc(sizeof(mDNSResourceRecord));
    if (rr == NULL)
        syserr("Malloc has failed");
    rr->qname = strdup(name);
    rr->qtype = RRTYPE_A;
    rr->qclass = 0x0001;
    rr->ttl = MDNS_TTL;
    rr->rdLength = 4;
    rr->rdData = mdns_copy_resource_record_rdData(rr->qtype, ip, 
        rr->rdLength);
    res = mdns_send_resource_records(sock, rr);

    free (rdData);
    free_mDNSResourceRecord(rr);

    return res;

}


int32_t mdns_send_PTR(int32_t sock, const char* name, const char* domain)
{
    int32_t res;
    mDNSResourceRecord* rr;

    if (name == NULL)
        return -1;
    if (strlen(name) > 255)
        return -1;
    if (domain == NULL)
        return -1;
    if (strlen(domain) > 255)
        return -1;


    rr = malloc(sizeof(mDNSResourceRecord));
    if (rr == NULL)
        syserr("Malloc has failed");
    rr->qname = strdup(name);
    rr->qtype = RRTYPE_PTR;
    rr->qclass = 0x8001;
    rr->ttl = MDNS_TTL;
    rr->rdData = strdup(domain);
    rr->rdLength = mdns_getlength_resource_record_rddata(rr->qtype, rr->rdData);
    
    res = mdns_send_resource_records(sock, rr);

    free_mDNSResourceRecord(rr);

    return res;

}




// Functions for parsing mDNS packets.


// Read in a domain name from the given buffer starting at the given
// offset.  This handles using domain name compression to jump around
// the data buffer, if needed.
static char* mdns_read_name(const unsigned char* data, uint32_t datalen, 
    int32_t offset)
{
    myString* res;
    res = myString_new();
    uint8_t tmp, newoffset;
    while((offset <= datalen) && ((tmp = util_get8(&data[offset])) != 0))
    {
        offset++;

        if ((tmp & 0xc0) == 0)
        {
            // First two bits are 00
            if (offset + tmp > datalen)
            {
                // Attempt to read past end of data!
                return myString_free(res, 1);
            }
            if (*(res->str) != '\0')
            {
                res = myString_append_char(res, '.');
            }
            res = myString_append_string(res, &data[offset], tmp);
            offset += tmp;
        }
        else if ((tmp & 0x40) == 0)
        {
            // First two bits are 10
            // Reserved for future use 
        }
        else if ((tmp & 0x80) == 0)
        {
            // First two bits are 01
            // Reserved for future use 
        }
        else
        {
            // First two bits are 11
            // Compression
            // Jump to another position in the data
            newoffset = util_get8(&data[offset]);
            if (newoffset >= offset)
                // Invalid pointer! Bailing!
                return myString_free(res, 1);
            offset = newoffset;
        }
    }
    if (offset > datalen)
        return myString_free(res, 1);

    return myString_free(res, 0);
}



// Determine how many bytes long a portion of the domain name is
// at the given offset.  This does NOT jump around the data array
// in the case of domain name compression.

static int32_t mdns_read_name_len(const unsigned char* data, uint32_t datalen, 
    int32_t offset)
{
    int32_t startoffset = offset;
    uint8_t tmp;

    while ((offset <= datalen) && ((tmp = util_get8(&data[offset])) != 0))
    {
        offset++;
        if ((tmp & 0xc0) == 0) 
        {   // First two bits are 00
            if (offset + tmp > datalen)
                // Attempt to read past end of data!
                return 0;
            offset += tmp;
        } 
        else if ((tmp & 0x40) == 0) 
        { 
            // First two bits are 10
            // Reserved for future use
        } 
        else if ((tmp & 0x80) == 1) 
        { 
            // First two bits are 01
            // Reserved for future use 
        } 
        else 
        { 
            // First two bits are 11
            // End of this portion of the domain name
            break;

        }
    }

    return offset - startoffset + 1;
}

static mDNSQuestion* mdns_read_question(const unsigned char* data, 
    uint32_t datalen, int32_t* offset)
{
    mDNSQuestion* q;

    q = (mDNSQuestion*) malloc(sizeof(mDNSQuestion));
    // QNAME
    q->qname = mdns_read_name(data, datalen, *offset);
    *offset += mdns_read_name_len(data, datalen, *offset);

    if (*offset + 4 > datalen)
    {
        free_mDNSQuestion(q);
        return NULL;
    }

    // QTYPE
    q->qtype = util_get16(&data[*offset]);
    *offset += 2;
    // QCLASS
    q->qclass = util_get16(&data[*offset]);
    *offset += 2;
    if (*offset > datalen)
    {
        free_mDNSQuestion(q);
        return NULL;
    }

    return q;
}

static List* mdns_read_questions(int32_t num_of_questions, 
    const unsigned char* data, uint32_t datalen, int32_t* offset)
{
    List* res = NULL;
    mDNSQuestion* q;
    int32_t i;

    for (i = 0; i < num_of_questions; i++)
    {
        q = mdns_read_question(data, datalen, offset);
        if (q == NULL)
            break;
        res = insertList(res, q);
    }


    // Malformed packet check
    if (i < num_of_questions)
    {
        free_mDNSQuestions(res);
        return NULL;
    }

    return res;
}

static unsigned char* mdns_read_resource_record_rdData_NULL (
    const unsigned char* data, uint32_t datalen, int32_t offset, 
    uint16_t rdLength)
{
    unsigned char* res = NULL;

    if (offset + rdLength > datalen)
        return NULL;

    res = (unsigned char*)malloc(rdLength);
    memcpy(res, &data[offset], rdLength);

    return res;
}

static char* mdns_read_resource_record_rdData_PTR(const unsigned char* data, 
    uint32_t datalen, int32_t offset)
{
    return mdns_read_name(data, datalen, offset);
}

static mDNSResourceRecord* mdns_read_resource_record(const unsigned char* data, 
    uint32_t datalen, int32_t* offset)
{
    mDNSResourceRecord* rr;
    rr = (mDNSResourceRecord*) malloc(sizeof(mDNSResourceRecord));

    if (rr == NULL)
        syserr("Malloc has failed you");

    // NAME
    rr->qname = mdns_read_name(data, datalen, *offset);
    *offset += mdns_read_name_len(data, datalen, *offset);

    // Malformed packet check
    if (*offset + 10 > datalen)
    {
        rr->rdData = NULL;
        free_mDNSResourceRecord(rr);
        return NULL;
    }

    // QTYPE
    rr->qtype = util_get16(&data[*offset]);
    *offset += 2;

    // QCLASS
    rr->qclass = util_get16(&data[*offset]);
    *offset += 2;

    // TTL
    rr->ttl = util_get32(&data[*offset]);
    *offset += 4;

    // RDLENGTH
    rr->rdLength = util_get16(&data[*offset]);
    *offset += 2;

    // RDDATA
    if (rr->qtype == RRTYPE_A)
    {
        rr->rdData = mdns_read_resource_record_rdData_NULL(data, datalen, 
            *offset, rr->rdLength);
        if (rr->rdData == NULL)
        {
            free_mDNSResourceRecord(rr);
            return NULL;
        }
    }
    else if (rr->qtype == RRTYPE_PTR)
    {
        rr->rdData = mdns_read_resource_record_rdData_PTR(data, datalen, 
            *offset);
        if (rr->rdData == NULL)
        {
            free_mDNSResourceRecord(rr);
            return NULL;
        }
    }
    else
    {
        rr->rdData = NULL;
        free_mDNSResourceRecord(rr);
        return NULL;
    }

    // Malformed packet check
    *offset += rr->rdLength;
    if (*offset > datalen)
    {
        free_mDNSResourceRecord(rr);
        return NULL;
    }

    return rr;
}

static List* mdns_read_resource_records(int32_t num_of_records, 
    const unsigned char* data, uint32_t datalen, int32_t* offset)
{
    List* res = NULL;
    mDNSResourceRecord* rr;
    int32_t i;

    for (i = 0; i < num_of_records; i++)
    {
        rr = mdns_read_resource_record(data, datalen, offset);
        if (rr == NULL)
            break;
        res = insertList(res, rr);
    }

    // Malformed packet check
    if (i < num_of_records)
    {
        free_mDNSResourceRecords(res);
        return NULL;
    }

    return res;
}

// Small helper function, is a response?
int8_t isResponse (uint16_t flags)
{
    return checkBit16(&flags, 15);
}

// Check if _udp is in name
int8_t has_udp (const char* name)
{
    char* b;
    b = strchr(name, '.');
    b++;
    if (strcmp(b, SERVICE_NAME_UDP) == 0)
        return 0;
    return -1;
}

// Check if _tcp is in name
int8_t has_tcp (const char* name)
{
    char* b;
    b = strchr(name, '.');
    b++;
    if (strcmp(b, SERVICE_NAME_TCP) == 0)
        return 0;
    return -1; 
}

// If invalid data is encountered at any point when parsing the data
// then the entire packet is discarded and NULL is returned.

mDNSPacket* mdns_read_packet(int32_t sock)
{

    mDNSPacket* mdns = NULL;
    // Current position in datagram
    int32_t offset;
    // Maximum incoming UDP packet size set to 512 - performance increased.
    unsigned char data[512];

    uint32_t datalen;
    struct sockaddr_in addr;
    socklen_t addrlen;


    /*addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(MDNS_PORT);*/

    // Read in an mDNS packet
    addrlen = sizeof(struct sockaddr_in);
    if ((datalen = recvfrom(sock, data, sizeof(data), 0, 
        (struct sockaddr*)&addr, &addrlen)) == -1)
    {
        syserr("Error in reading packet");
        return NULL;
    }


    mdns = (mDNSPacket*)malloc(sizeof(mDNSPacket));

    // Parse the incoming packet, starting from 0
    offset = 0;

    if (offset + 12 > datalen)
    {
        free(mdns);
        return NULL;
    }


    // Header section
    mdns->header = malloc(sizeof(mDNSHeader));
    if (mdns->header == NULL)
        syserr("Malloc ");

    // ID
    mdns->header->id = util_get16(&data[offset]);
    offset += 2;

    // For the flags some bits must be 0, some 1, rest are ignored
    mdns->header->flags = util_get16(&data[offset]);
    offset += 2;
    if ((mdns->header->flags & 0x7800) != 0)
    {
        // OPCODE should be all 0's
        free(mdns->header);
        free(mdns);
        return NULL;
    }

    // Read the number of questions, answers and other things in packet
    mdns->header->num_of_questions = util_get16(&data[offset]);
    offset += 2;
    mdns->header->num_of_answers = util_get16(&data[offset]);
    offset += 2;
    mdns->header->authority_num = util_get16(&data[offset]);
    offset += 2;
    mdns->header->additional_num = util_get16(&data[offset]);
    offset += 2;


    // Read in all the questions
    mdns->questions = mdns_read_questions(mdns->header->num_of_questions, data, 
        datalen, &offset);


    // Read in all the answers
    mdns->answers = mdns_read_resource_records(mdns->header->num_of_answers, 
        data, datalen, &offset);

    mdns->authority = NULL;
    mdns->additional = NULL;

    // Yeah we ignore all the other data so what
    // So checking only for malformation of what we need
    if (((mdns->header->num_of_questions > 0) && (mdns->questions == NULL)) ||
        ((mdns->header->num_of_answers > 0) && (mdns->answers == NULL)))
    {
        free_mDNSPacket(mdns);
        return NULL;
    }
    // We do not check if we are at the end, so what?
    /*
        if (offset != datalen)
        {
            free(mdns);
            return NULL;
        }
    */

    // Here we should cache our data.
    if (isResponse(mdns->header->flags) == 1)
    {
        // Ok it is a response, not a question, we need only responses in cache
        if (mdns->header->num_of_answers > 0)
        {
            List* cur;
            for (cur = (List*) mdns->answers; cur != NULL; cur = cur->next)
            {
                if (((mDNSResourceRecord*)cur->data)->qtype == RRTYPE_PTR)
                {

                    if (has_udp((const char*)
                        ((mDNSResourceRecord*)cur->data)->rdData) == 0)
                    {

                        // Ok add name to cache, we do not know ip yet. no tcp.
                        mdns_cache_add((const char*)
                            ((mDNSResourceRecord*)cur->data)->rdData, NULL, 0);
                        // Ask for Address (RRTYPE_A)
                        if (mdns_send_query(sock, (const char*)
                            ((mDNSResourceRecord*)cur->data)->rdData, 
                            RRTYPE_A) < 0)
                        {
                            syserr("Error in sending query A");
                        }
                    }
                    else if (has_tcp((const char*)
                        ((mDNSResourceRecord*)cur->data)->rdData) == 0)
                    {
                        // Ok add name to cache, we do not know ip yet. has tcp.
                        mdns_cache_add((const char*)
                            ((mDNSResourceRecord*)cur->data)->rdData, NULL, 1);
                        // Ask for Address (RRTYPE_A)
                        if (mdns_send_query(sock, (const char*)
                            ((mDNSResourceRecord*)cur->data)->rdData, 
                            RRTYPE_A) < 0)
                        {
                            syserr("Error in sending query A");
                        }
                    }

                }
                else if (((mDNSResourceRecord*)cur->data)->qtype == RRTYPE_A)
                {
                    // Ok add that address to cache.
                    if (has_udp((const char*)
                        ((mDNSResourceRecord*)cur->data)->qname) == 0)
                    {
                        // Update cache if necessary.
                        mdns_cache_add_ip(
                            ((mDNSResourceRecord*)cur->data)->qname, 
                            (unsigned char*) 
                            ((mDNSResourceRecord*)cur->data)->rdData, 0);
                        // Nothing else to do.
                    }
                    else if(has_tcp((const char*)
                        ((mDNSResourceRecord*)cur->data)->qname) == 0)
                    {
                        // Update cache if necessary.
                        mdns_cache_add_ip(
                            ((mDNSResourceRecord*)cur->data)->qname, 
                            (unsigned char*) 
                            ((mDNSResourceRecord*)cur->data)->rdData, 1);
                        // Nothing else to do.
                    }
                    
                }
            }
        }
        
    }
    else
    {
        // Is a question, ok we should reply to it.
        if (mdns->header->num_of_questions > 0)
        {
            List* cur;
            for (cur = (List*) mdns->questions; cur != NULL; cur = cur->next)
            {
                
                if (((mDNSQuestion*)(cur->data))->qtype == RRTYPE_PTR)
                {
                    if (strcmp((const char*)
                        (((mDNSQuestion*)(cur->data))->qname),
                        (SERVICE_NAME_UDP)) == 0)
                    {
                        // Send our very funny domain name. UDP IS ON.
                        if (mdns_send_PTR(sock, 
                            ((mDNSQuestion*)(cur->data))->qname, 
                            MDNS_DOMAIN_UDP) < 0)
                        {
                            syserr("Error in sending PTR");
                        }
                    }
                    else if (strcmp((const char*)
                        (((mDNSQuestion*)(cur->data))->qname), 
                        (SERVICE_NAME_TCP)) == 0)
                    {
                        // Send our very funny domain name if TCP is on.
                        if (USE_TCP == 1)
                            if (mdns_send_PTR(sock, 
                                (((mDNSQuestion*)(cur->data))->qname), 
                                MDNS_DOMAIN_TCP) < 0)
                            {
                                syserr("Error in sending PTR");
                            }
                    }
                    
                }
                else if (((mDNSQuestion*)(cur->data))->qtype == RRTYPE_A)
                {
                    // Send our address. (On our address)
                    mdns_send_A(sock, 
                        ((mDNSQuestion*)(cur->data))->qname, MDNS_IP);
                    if (strcmp((const char*)((mDNSQuestion*)cur->data)->qname, 
                        (MDNS_DOMAIN_UDP)) == 0)
                    {
                        // Send our address. UDP IS ON.
                        if (mdns_send_A(sock, 
                            ((mDNSQuestion*)(cur->data))->qname, MDNS_IP) < 0)
                        {
                            syserr("Error in sending A");
                        }
                    }
                    else if (strcmp((const char*)
                        ((mDNSQuestion*)(cur->data))->qname, 
                        (MDNS_DOMAIN_TCP)) == 0)
                    {
                        // Send our address if TCP is on.
                        if (USE_TCP == 1)
                            if (mdns_send_A(sock, 
                                ((mDNSQuestion*)(cur->data))->qname, 
                                MDNS_IP) < 0)
                            {
                                syserr("Error in sending A");
                            }
                    }
                }
            }
        }

    }

    return mdns;  
}


int32_t mdns_check_if_read_answer_A(int32_t sock)
{
    mDNSPacket* mdns = NULL;
    // Current position in datagram
    int32_t offset;
    // Maximum incoming UDP packet size set to 512 - performance increased.
    unsigned char data[512];

    uint32_t datalen;
    struct sockaddr_in addr;
    socklen_t addrlen;

    struct pollfd ufds[1];

    ufds[0].fd = sock;
    ufds[0].events = POLLIN;
    int rv;

    if ((rv = poll(ufds, 1, 200)) == -1)
        return 0;
    else if (rv == 0)
    {
        return 0;
    }
    else if (!(ufds[0].revents & POLLIN))
    {
        return 0;
    }

    // Read in an mDNS packet
    addrlen = sizeof(struct sockaddr_in);
    if ((datalen = recvfrom(sock, data, sizeof(data), 0, 
        (struct sockaddr*)&addr, &addrlen)) == -1)
    {
        //syserr("Error in reading packet");
        return 0;
    }


    mdns = (mDNSPacket*)malloc(sizeof(mDNSPacket));

    // Parse the incoming packet, starting from 0
    offset = 0;

    if (offset + 12 > datalen)
    {
        free(mdns);
        return 0;
    }


    // Header section
    mdns->header = malloc(sizeof(mDNSHeader));
    if (mdns->header == NULL)
        syserr("Malloc ");

    // ID
    mdns->header->id = util_get16(&data[offset]);
    offset += 2;

    // For the flags some bits must be 0, some 1, rest are ignored
    mdns->header->flags = util_get16(&data[offset]);
    offset += 2;
    if ((mdns->header->flags & 0x7800) != 0)
    {
        // OPCODE should be all 0's
        free(mdns->header);
        free(mdns);
        return 0;
    }

    // Read the number of questions, answers and other things in packet
    mdns->header->num_of_questions = util_get16(&data[offset]);
    offset += 2;
    mdns->header->num_of_answers = util_get16(&data[offset]);
    offset += 2;
    mdns->header->authority_num = util_get16(&data[offset]);
    offset += 2;
    mdns->header->additional_num = util_get16(&data[offset]);
    offset += 2;


    // Read in all the questions
    mdns->questions = mdns_read_questions(mdns->header->num_of_questions, data, 
        datalen, &offset);


    // Read in all the answers
    mdns->answers = mdns_read_resource_records(mdns->header->num_of_answers, 
        data, datalen, &offset);

    mdns->authority = NULL;
    mdns->additional = NULL;

    // Yeah we ignore all the other data so what
    // So checking only for malformation of what we need
    if (((mdns->header->num_of_questions > 0) && (mdns->questions == NULL)) ||
        ((mdns->header->num_of_answers > 0) && (mdns->answers == NULL)))
    {
        free_mDNSPacket(mdns);
        return 0;
    }

    // Here we should cache our data.
    if (isResponse(mdns->header->flags) == 1)
    {
        // Ok it is a response, not a question, we need only responses in cache
        if (mdns->header->num_of_answers > 0)
        {
            List* cur;
            for (cur = (List*) mdns->answers; cur != NULL; cur = cur->next)
            {
                // Only care about A
                if (((mDNSResourceRecord*)cur->data)->qtype == RRTYPE_A)
                {
                    // Ok add that address to cache.
                    if (strcmp(((const char*)
                        ((mDNSResourceRecord*)cur->data)->qname), 
                        MDNS_DOMAIN_UDP) == 0)
                    {
                        free_mDNSPacket(mdns);
                        // SOMEONE HAS OUR NAME
                        return -1;
                    }
                    // TCP is of no concern we are asking for udp. But what the 
                    // hell, we can check that
                    else if (strcmp(((const char*)
                        ((mDNSResourceRecord*)cur->data)->qname), 
                        MDNS_DOMAIN_TCP) == 0)
                    {
                        free_mDNSPacket(mdns);
                        // SOMEONE HAS OUR NAME
                        return -1;
                    }
                    
                }
            }
        }
        
    }
    // else ignore
    
    free_mDNSPacket(mdns);
    return 0;  
}



// Checks if name is available.
int8_t check_if_name_available(int32_t sock, const char* name)
{
    int res = 0;
    int i = 0;
    while (i < 10)
    {
        mdns_send_A(sock, MDNS_DOMAIN_UDP, MDNS_IP);
        int j = 0;
        // Check if we got our rply?
        for(j = 0; j < 3; j++)
        {
            if ((res = mdns_check_if_read_answer_A(sock)) == -1)
            {
                return -1;
            }

        }
        i++;
    }
    
    return res;
}

char* get_more_random_name(char* name)
{
    int forgenerator = time(NULL);
    srand(forgenerator);
    int len = strlen(name);
    char* res = malloc(len + 2);
    int i = 0;

    while (i < len - 1)
    {
        res[i] = name[i];
        i++;
    }

    res[len - 1] = (rand() % 10) + 48;
    res[len] = '.'; 
    res[len + 1] = '\0';
    free(name);
    return res;
}


// Updates the service names
void update_mdns_names ()
{
    int cmp_len = strlen(COMPUTER_NAME);
    int udp_len = strlen(SERVICE_NAME_UDP);
    int tcp_len = strlen(SERVICE_NAME_TCP);

    if (MDNS_DOMAIN_UDP != NULL)
        free(MDNS_DOMAIN_UDP);
    if (MDNS_DOMAIN_TCP != NULL)
        free(MDNS_DOMAIN_TCP);
    MDNS_DOMAIN_UDP = malloc(cmp_len + udp_len + 1);
    MDNS_DOMAIN_TCP = malloc(cmp_len + tcp_len + 1);

    int i = 0;

    while (i < cmp_len)
    {
        MDNS_DOMAIN_UDP[i] = COMPUTER_NAME[i];
        i++;
    }

    i = 0;

    while (i < udp_len)
    {
        MDNS_DOMAIN_UDP[i + cmp_len] = SERVICE_NAME_UDP[i];
        i++;
    }

    MDNS_DOMAIN_UDP[cmp_len + udp_len] = '\0';

    i = 0;

    while (i < cmp_len)
    {
        MDNS_DOMAIN_TCP[i] = COMPUTER_NAME[i];
        i++;
    }

    i = 0;

    while (i < tcp_len)
    {
        MDNS_DOMAIN_TCP[i + cmp_len] = SERVICE_NAME_TCP[i];
        i++;
    }

    MDNS_DOMAIN_TCP[cmp_len + tcp_len] = '\0';
}

// Initialize our domain name
void init_mdns_domain(int32_t sock)
{
    printf("Inicjuje nowa nazwe dla komputera\n");
    COMPUTER_NAME = strdup(BASE_NAME);
    COMPUTER_NAME = get_more_random_name(COMPUTER_NAME);
    update_mdns_names();

    int available = 0;
    while ((available = check_if_name_available(sock, COMPUTER_NAME)) != 0)
    {
        COMPUTER_NAME = get_more_random_name(COMPUTER_NAME);
        update_mdns_names();
    }
    printf("Gotowe : %s\n", COMPUTER_NAME);
    

}

// Initialize our ip
void init_mdns_ip()
{
    MDNS_IP = malloc(4);

    struct ifaddrs *ifaddr, *ifa;
    int s;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1)
        syserr("getifaddrs");


    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;

        s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, 
            NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

        if ((strcmp(ifa->ifa_name, INTERNET_INTERFACE_WLAN) == 0) && 
            (ifa->ifa_addr->sa_family == AF_INET))
        {
            if (s != 0)
                syserr("Getnameinfo failed");

            // Put the address to MDNS_IP
            uint32_t host_int = inet_addr(host);

            MDNS_IP[0] = (unsigned char) ((host_int) & 0xff);
            MDNS_IP[1] = (unsigned char) ((host_int >> 8) & 0xff);
            MDNS_IP[2] = (unsigned char) ((host_int >> 16) & 0xff);
            MDNS_IP[3] = (unsigned char) ((host_int >> 24) & 0xff);
            break;

        }
        if ((strcmp(ifa->ifa_name, INTERNET_INTERFACE_ETH) == 0) && 
            (ifa->ifa_addr->sa_family == AF_INET))
        {
            if (s != 0)
                syserr("Getnameinfo failed");

            // Put the address to MDNS_IP
            uint32_t host_int = inet_addr(host);

            MDNS_IP[0] = (unsigned char) ((host_int) & 0xff);
            MDNS_IP[1] = (unsigned char) ((host_int >> 8) & 0xff);
            MDNS_IP[2] = (unsigned char) ((host_int >> 16) & 0xff);
            MDNS_IP[3] = (unsigned char) ((host_int >> 24) & 0xff);
            break;

        }
    }

    freeifaddrs(ifaddr);

}




#endif