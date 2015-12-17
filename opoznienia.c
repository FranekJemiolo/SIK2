// This program was written by Franciszek Jemioło, index number 346919.
// This program is: a server for measurement of udp connection latency,
// a client for measuring udp, tcp, and icmp connection latency.
// It is also an mDNS server and client.
// It also has user interface for telnet connections
#include "opoznienia.h"
#include "ui.h"
#define UDP_OPTION "-u\0"
#define TELNET_PORT_OPTION "-U\0"
#define LATENCY_MEASURE_OPTION "-t\0"
#define COMPUTER_SCAN_OPTION "-T\0"
#define INTERFACE_UPDATE_OPTION "-v\0"
#define USE_TCP_OPTION "-s\0"
#define SSH_PORT "22"


typedef struct _MeasureStruct
{
    unsigned char* ip;
    char* name;
} MeasureStruct;

uint64_t GetTimeStamp() 
{
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return (((tv.tv_sec) * (1000000ull)) + tv.tv_usec);
}


// Thread for measuring udp -- client
void* measure_latency_udp(void* ms_ptr)
{

    MeasureStruct* ms = (MeasureStruct*) ms_ptr;
    // All the necessary variables
    myString* s;
    char* host_name;

    s = myString_new();
    char ip1[5];
    sprintf(ip1, "%d", ms->ip[0]);
    s = myString_append_string(s, ip1, strlen(ip1));
    s = myString_append_char(s, '.');
    char ip2[5];
    sprintf(ip2, "%d", ms->ip[1]);
    s = myString_append_string(s, ip2, strlen(ip2));
    s = myString_append_char(s, '.');
    char ip3[5];
    sprintf(ip3, "%d", ms->ip[2]);
    s = myString_append_string(s, ip3, strlen(ip3));
    s = myString_append_char(s, '.');
    char ip4[5];
    sprintf(ip4, "%d", ms->ip[3]);
    s = myString_append_string(s, ip4, strlen(ip4));

    host_name = myString_free(s, 0);


    int sock;
    int spot;
    struct addrinfo addr_hints;
    struct addrinfo *addr_result;

    int flags, sflags;
    uint64_t datagram_sent[SEND_SIZE];
    uint64_t datagram_returned[RETURN_SIZE];
    size_t len;
    ssize_t snd_len, rcv_len;
    struct sockaddr_in my_address;
    struct sockaddr_in srvr_address;
    socklen_t rcva_len;

    char port_num[10];    
    sprintf(port_num, "%d", htons(UDP_PORT_NUM));

    // Converting host/port in string to struct addrinfo
    (void) memset(&addr_hints, 0, sizeof(struct addrinfo));
    addr_hints.ai_family = AF_INET; // IPv4
    addr_hints.ai_socktype = SOCK_DGRAM;
    addr_hints.ai_protocol = IPPROTO_UDP;
    addr_hints.ai_flags = 0;
    addr_hints.ai_addrlen = 0;
    addr_hints.ai_addr = NULL;
    addr_hints.ai_canonname = NULL;
    addr_hints.ai_next = NULL;
    if (getaddrinfo(host_name, port_num, &addr_hints, &addr_result) != 0) 
    {
        syserr("getaddrinfo");
    }


    // IPv4
    my_address.sin_family = AF_INET;
    // Address IP
    my_address.sin_addr.s_addr =
        ((struct sockaddr_in*) (addr_result->ai_addr))->sin_addr.s_addr;
    // Port from the command line.
    my_address.sin_port = htons((uint16_t)(UDP_PORT_NUM));

    freeaddrinfo(addr_result);


    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        syserr("socket");

    struct timeval timeout;      
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    if (setsockopt (sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
                sizeof(timeout)) < 0)
        syserr("setsockopt failed\n");

    if (setsockopt (sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
                sizeof(timeout)) < 0)
        syserr("setsockopt failed\n");

    // Sending the datagram.
    uint64_t ping_time;
    uint64_t before = GetTimeStamp();
    // Converting to big-endian.
    uint64_t current = htobe64(before);
    len = (size_t)(sizeof(datagram_sent));
    datagram_sent[0] = current;

    sflags = 0;
    rcva_len = (socklen_t) sizeof(my_address);
    //printf("Pisze do ziomeczka\n");
    pthread_rwlock_wrlock(&cache_rwlock);
    spot = mdns_cache_find(ms->name);
    if (spot >= 0)
    {
        mDNSCache[spot]->times_rply++;
    }
    pthread_rwlock_unlock(&cache_rwlock);
    snd_len = sendto(sock, datagram_sent, len, sflags,
        (struct sockaddr *) &my_address, rcva_len);

    if (snd_len != (ssize_t) len) 
    {
        if (errno == EWOULDBLOCK)
        {
            // Timeout
            printf("Timeout\n");
            errno = 0;
            free(ms->ip);
            free(ms->name);
            free(ms);
            free(host_name);
            if (close(sock) == -1) 
            {
                // it's healthy to do the check.
                syserr("close"); 
            };
            return NULL;
        }
        else if (snd_len >= 0)
        {
            printf("Other error, treat like Timeout\n");
            errno = 0;
            free(ms->ip);
            free(ms->name);
            free(ms);
            free(host_name);
            if (close(sock) == -1) 
            {
                // it's healthy to do the check.
                syserr("close"); 
            };
            return NULL;
        }
        else
        {
            syserr("Failed write");
        }
        
    }


    // Now getting the return datagrams.
    (void) memset(datagram_returned, 0, sizeof(datagram_returned));

    flags = 0;
    len = (size_t) sizeof(datagram_returned);
    rcva_len = (socklen_t) sizeof(srvr_address);


    rcv_len = recvfrom(sock, datagram_returned, len, flags,
        (struct sockaddr *) &srvr_address, &rcva_len);

    if (errno == EWOULDBLOCK)
    {
        // Timeout
        //printf("Timeout\n");
        errno = 0;
        free(ms->ip);
        free(ms->name);
        free(ms);
        free(host_name);
        if (close(sock) == -1) 
        {
            // it's healthy to do the check.
            syserr("close"); 
        };
        return NULL;
    }
    else if (rcv_len < 0) 
    {
        //printf("Other error, treat like Timeout\n");
        errno = 0;
        free(ms->ip);
        free(ms->name);
        free(ms);
        free(host_name);
        if (close(sock) == -1) 
        {
            // it's healthy to do the check.
            syserr("close"); 
        };
        return NULL;
    }
    uint64_t after = GetTimeStamp();
    ping_time = after - before;
    pthread_rwlock_wrlock(&cache_rwlock);
    spot = mdns_cache_find(ms->name);
    if (spot >= 0)
    {
        mDNSCache[spot]->times_rply--;
    }
    pthread_rwlock_unlock(&cache_rwlock);

    int inserted = (int) (ping_time / 1000);

    insert_latency(host_name, inserted, -1, -1);
    //sort_latencies();
    
    free(ms->ip);
    free(ms->name);
    free(ms);
    free(host_name);
    // Very rare errors can occur here, but then
    
    if (close(sock) == -1) 
    {
        // it's healthy to do the check.
        syserr("close"); 
    };
    return NULL;
}

// Thread for measuring tcp -- client
void* measure_latency_tcp(void* ms_ptr)
{
    MeasureStruct* ms = (MeasureStruct*) ms_ptr;
    // Just the necessary variables.
    int sock;
    struct addrinfo addr_hints;
    struct addrinfo *addr_result;

    int err;
    int spot;
    myString* s;
    char* host_name;

    s = myString_new();
    char ip1[5];
    sprintf(ip1, "%d", ms->ip[0]);

    s = myString_append_string(s, ip1, strlen(ip1));
    s = myString_append_char(s, '.');
    char ip2[5];
    sprintf(ip2, "%d", ms->ip[1]);
    s = myString_append_string(s, ip2, strlen(ip2));
    s = myString_append_char(s, '.');
    char ip3[5];
    sprintf(ip3, "%d", ms->ip[2]);
    s = myString_append_string(s, ip3, strlen(ip3));
    s = myString_append_char(s, '.');
    char ip4[5];
    sprintf(ip4, "%d", ms->ip[3]);
    s = myString_append_string(s, ip4, strlen(ip4));


    host_name = myString_free(s, 0);

    // Converting host/port in string to struct addrinfo
    memset(&addr_hints, 0, sizeof(struct addrinfo));
    // IPv4
    addr_hints.ai_family = AF_INET; 
    addr_hints.ai_socktype = SOCK_STREAM;
    addr_hints.ai_protocol = IPPROTO_TCP;

    err = getaddrinfo(host_name, SSH_PORT, &addr_hints, &addr_result);
    if (err != 0)
        syserr("getaddrinfo: %s\n", gai_strerror(err));

    // initialize socket according to getaddrinfo results
    sock = socket(addr_result->ai_family, addr_result->ai_socktype, 
        addr_result->ai_protocol);
    if (sock < 0)
        syserr("socket");


    int res; 
    fd_set myset; 
    struct timeval tv;
    long arg;
    socklen_t lon;
    int valopt;

    // Set non-blocking 
    if( (arg = fcntl(sock, F_GETFL, NULL)) < 0) { 
        syserr("fcntl");
        exit(0); 
    } 
    arg |= O_NONBLOCK; 
    if( fcntl(sock, F_SETFL, arg) < 0) { 
        syserr("fcntl");
        exit(0); 
    } 


    uint64_t before, after, ping_time;
    // Getting time stamp before connection.
    before = GetTimeStamp();


    pthread_rwlock_wrlock(&cache_rwlock);
    spot = mdns_cache_find(ms->name);
    if (spot >= 0)
    {
        mDNSCache[spot]->times_rply++;
    }
    pthread_rwlock_unlock(&cache_rwlock);

    // connect socket to the server
    res = connect(sock, addr_result->ai_addr, addr_result->ai_addrlen);

    if (res < 0) 
    { 
        if (errno == EINPROGRESS) 
        { 
            errno = 0;
            tv.tv_sec = 10; 
            tv.tv_usec = 0; 
            FD_ZERO(&myset); 
            FD_SET(sock, &myset); 
            res = select(sock+1, NULL, &myset, NULL, &tv); 
            if (res < 0 && errno != EINTR) 
            { 
                errno = 0;
                freeaddrinfo(addr_result);
                free(ms->ip);
                free(ms->name);
                free(ms);
                free(host_name);
                if (close(sock) == -1) 
                {
                    // it's healthy to do the check.
                    syserr("close"); 
                };
                return NULL;
            } 
            else if (res > 0) 
            { 
                // Socket selected for write 
                lon = sizeof(int); 
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (void*)(&valopt), 
                    &lon) < 0) 
                { 
                    errno = 0;
                    freeaddrinfo(addr_result);
                    free(ms->ip);
                    free(ms->name);
                    free(ms);
                    free(host_name);
                    if (close(sock) == -1) 
                    {
                        // it's healthy to do the check.
                        syserr("close"); 
                    };
                    return NULL;
                } 
                // Check the value returned... 
                if (valopt) 
                { 
                    errno = 0;
                    freeaddrinfo(addr_result);
                    free(ms->ip);
                    free(ms->name);
                    free(ms);
                    free(host_name);
                    if (close(sock) == -1) 
                    {
                        // it's healthy to do the check.
                        syserr("close"); 
                    };
                    return NULL;
                }
            } 
            else 
            { 
                errno = 0;
                freeaddrinfo(addr_result);
                free(ms->ip);
                free(ms->name);
                free(ms);
                free(host_name);
                if (close(sock) == -1) 
                {
                    // it's healthy to do the check.
                    syserr("close"); 
                };
                return NULL;
            } 
        } 
        else 
        { 
            errno = 0;
            freeaddrinfo(addr_result);
            free(ms->ip);
            free(ms->name);
            free(ms);
            free(host_name);
            if (close(sock) == -1) 
            {
                // it's healthy to do the check.
                syserr("close"); 
            };
            return NULL;
        } 
    } 
    errno = 0;
    pthread_rwlock_wrlock(&cache_rwlock);
    spot = mdns_cache_find(ms->name);
    if (spot >= 0)
    {
        mDNSCache[spot]->times_rply--;
    }
    pthread_rwlock_unlock(&cache_rwlock);
    // Getting time stamp after connection.
    after = GetTimeStamp();
    ping_time = after - before;

    int inserted = (int) (ping_time / 1000);

    insert_latency(host_name, -1, inserted, -1);
    //sort_latencies();

    free(host_name);
    freeaddrinfo(addr_result);
    // We are just connecting so we won't send any data.
    free(ms->ip);
    free(ms->name);
    free(ms);
    (void) close(sock);
    return NULL; 
}

// Thread for measuring icmp -- client
void* measure_latency_icmp(void* ms_ptr)
{
    int sock;

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0)
        syserr("socket");

    struct timeval timeout;      
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    if (setsockopt (sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
                sizeof(timeout)) < 0)
        syserr("setsockopt failed\n");

    if (setsockopt (sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
                sizeof(timeout)) < 0)
        syserr("setsockopt failed\n");

    //drop_to_nobody();

    // First we send the request.

    MeasureStruct* ms = (MeasureStruct*) ms_ptr;

    struct addrinfo addr_hints;
    struct addrinfo *addr_result;
    struct sockaddr_in send_addr;

    struct icmp* icmp;

    char send_buffer[BSIZE];
    char buf[BSIZE];
    int spot;

    int err = 0;
    ssize_t data_len = 0;
    ssize_t icmp_len = 0;
    ssize_t len = 0;

    myString* s;
    char* s_send_addr;

    s = myString_new();
    char ip1[5];
    sprintf(ip1, "%d", ms->ip[0]);
    s = myString_append_string(s, ip1, strlen(ip1));
    s = myString_append_char(s, '.');
    char ip2[5];
    sprintf(ip2, "%d", ms->ip[1]);
    s = myString_append_string(s, ip2, strlen(ip2));
    s = myString_append_char(s, '.');
    char ip3[5];
    sprintf(ip3, "%d", ms->ip[2]);
    s = myString_append_string(s, ip3, strlen(ip3));
    s = myString_append_char(s, '.');
    char ip4[5];
    sprintf(ip4, "%d", ms->ip[3]);
    s = myString_append_string(s, ip4, strlen(ip4));

    s_send_addr = myString_free(s, 0);


    // 'converting' host/port in string to struct addrinfo
    memset(&addr_hints, 0, sizeof(struct addrinfo));
    addr_hints.ai_family = AF_INET;
    addr_hints.ai_socktype = SOCK_RAW;
    addr_hints.ai_protocol = IPPROTO_ICMP;
    err = getaddrinfo(s_send_addr, 0, &addr_hints, &addr_result);
    if (err != 0)
        syserr("getaddrinfo: %s\n", gai_strerror(err));


    send_addr.sin_family = AF_INET;
    send_addr.sin_addr.s_addr =
        ((struct sockaddr_in*) (addr_result->ai_addr))->sin_addr.s_addr;
    send_addr.sin_port = htons(0);
    freeaddrinfo(addr_result);

    memset(send_buffer, 0, sizeof(send_buffer));
    // initializing ICMP header
    icmp = (struct icmp *) send_buffer;
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_id = htons(getpid()); // process identified by PID
    icmp->icmp_seq = htons(0); // sequential number
    uint64_t curr = GetTimeStamp();
    sprintf(buf, "%" PRIu64, curr);

    int i = ICMP_HEADER_LEN;
    int l = strlen(buf);


    for (i = 0; i < l; i++)
    {
        send_buffer[i+ICMP_HEADER_LEN] = buf[i];
    }
    send_buffer[l+ICMP_HEADER_LEN+1] = '\0';

    data_len = (ICMP_HEADER_LEN + strlen(buf)) * sizeof(char);
    if (data_len < 1)
        syserr("snprinf");
    icmp_len = data_len + ICMP_HEADER_LEN; // packet is filled with 0
    icmp->icmp_cksum = 0; // checksum computed over whole ICMP package
    icmp->icmp_cksum = in_cksum((unsigned short*) icmp, icmp_len);

    pthread_rwlock_wrlock(&cache_rwlock);
    spot = mdns_cache_find(ms->name);
    if (spot >= 0)
    {
        mDNSCache[spot]->times_rply++;
    }
    pthread_rwlock_unlock(&cache_rwlock);

    len = sendto(sock, (void*) icmp, icmp_len, 0, 
        (struct sockaddr *) &send_addr, (socklen_t) sizeof(send_addr));

    if (errno == EWOULDBLOCK)
    {
        // Timeout
        errno = 0;
        free(ms->ip);
        free(ms->name);
        free(ms);
        free(s_send_addr);
        if (close(sock) == -1) 
        {
            // it's healthy to do the check.
            syserr("close"); 
        };
        return NULL;
    }
    else if (len != icmp_len) 
    {
        errno = 0;
        free(ms->ip);
        free(ms->name);
        free(ms);
        free(s_send_addr);
        if (close(sock) == -1) 
        {
            // it's healthy to do the check.
            syserr("close"); 
        };
        return NULL;
    }

    // Now let's wait for reply.
    int returned_val = 0;
    int time_passed = 0;
    while ((!returned_val) && (time_passed < 10000))
    {
        struct sockaddr_in rcv_addr1;
        socklen_t rcv_addr_len1;

        struct ip* ip1;
        struct icmp* icmp1;

        char rcv_buffer1[BSIZE];

        ssize_t ip_header_len1 = 0;
        ssize_t icmp_len1 = 0;
        ssize_t len1;

        memset(rcv_buffer1, 0, sizeof(rcv_buffer1));
        rcv_addr_len1 = (socklen_t) sizeof(rcv_addr1);
        len1 = recvfrom(sock, (void*) rcv_buffer1, sizeof(rcv_buffer1), 0, 
            (struct sockaddr *) &rcv_addr1, &rcv_addr_len1);
        if (errno == EWOULDBLOCK)
        {
            // Timeout
            errno = 0;
            continue;
            /*free(ms->ip);
            free(ms->name);
            free(ms);
            free(s_send_addr);
            if (close(sock) == -1) 
            {
                // it's healthy to do the check.
                syserr("close"); 
            };
            return NULL;*/
        }
        else if (len1 < 0) 
        {
            //printf("Other error, treat like Timeout\n");
            errno = 0;
            continue;
            /*free(ms->ip);
            free(ms->name);
            free(ms);
            free(s_send_addr);
            if (close(sock) == -1) 
            {
                // it's healthy to do the check.
                syserr("close"); 
            };
            return NULL;*/
        }

        uint64_t act = GetTimeStamp();
        time_passed += ((act - curr) / 1000);

        // recvfrom returns whole packet (with IP header)
        ip1 = (struct ip*) rcv_buffer1;
        ip_header_len1 = ip1->ip_hl << 2; // IP header len is in 4-byte words

        // ICMP header follows IP
        icmp1 = (struct icmp*) (rcv_buffer1 + ip_header_len1);
        icmp_len1 = len1 - ip_header_len1;

        if (icmp_len1 < ICMP_HEADER_LEN)
        {
            returned_val = 0;
            continue;
        }

        if (icmp1->icmp_type != ICMP_ECHOREPLY) {
            returned_val = 0;
            continue;
        }

        if (ntohs(icmp1->icmp_id) != getpid())
        {
            returned_val = 0;
            continue;
        }


        pthread_rwlock_wrlock(&cache_rwlock);
        spot = mdns_cache_find(ms->name);
        if (spot >= 0)
        {
            mDNSCache[spot]->times_rply--;
        }
        pthread_rwlock_unlock(&cache_rwlock);
        uint64_t after = GetTimeStamp();

        int ping_time = ((after-curr) / 1000);
        insert_latency(s_send_addr, -1, -1, ping_time);
        //sort_latencies();

        returned_val = 1;
        break;
    }
    
    free(s_send_addr);
    free(ms->ip);
    free(ms->name);
    free(ms);
    (void) close(sock);
    return NULL;
}

// Inits the measurement, creates new threads to connect to addresses in cache.
void* measure_latencies(void* data)
{
    pthread_t t;
    MeasureStruct* ms;
    // Wait and measure
    for (;;)
    {
        sleep(MDNS_LATENCY_RATE);
        pthread_rwlock_rdlock(&cache_rwlock);
        int i = 0;
        for (i = 0; i < MAX_CACHE_SIZE; i++)
        {
            if (mDNSCache[i] != NULL)
            {
                if (mDNSCache[i]->ip != NULL)
                {
                    if (USE_TCP == 1)
                    {
                        if (mDNSCache[i]->has_tcp == 1)
                        {
                            ms = malloc(sizeof(MeasureStruct));
                            ms->ip = malloc(4);
                            ms->ip[0] = mDNSCache[i]->ip[0];
                            ms->ip[1] = mDNSCache[i]->ip[1];
                            ms->ip[2] = mDNSCache[i]->ip[2];
                            ms->ip[3] = mDNSCache[i]->ip[3];
                            ms->name = strdup(mDNSCache[i]->service_name);
                            pthread_create(&t, 0, measure_latency_tcp, ms);
                            pthread_detach(t);
                        }
                    }
                    if (mDNSCache[i]->has_tcp != 1)
                    {
                        ms = malloc(sizeof(MeasureStruct));
                        ms->ip = malloc(sizeof(4));
                        ms->ip[0] = mDNSCache[i]->ip[0];
                        ms->ip[1] = mDNSCache[i]->ip[1];
                        ms->ip[2] = mDNSCache[i]->ip[2];
                        ms->ip[3] = mDNSCache[i]->ip[3];
                        ms->name = strdup(mDNSCache[i]->service_name);
                        pthread_create(&t, 0, measure_latency_udp, ms);
                        pthread_detach(t);
                    }
                    ms = malloc(sizeof(MeasureStruct));
                    ms->ip = malloc(sizeof(4));
                    ms->ip[0] = mDNSCache[i]->ip[0];
                    ms->ip[1] = mDNSCache[i]->ip[1];
                    ms->ip[2] = mDNSCache[i]->ip[2];
                    ms->ip[3] = mDNSCache[i]->ip[3];
                    ms->name = strdup(mDNSCache[i]->service_name);
                    pthread_create(&t, 0, measure_latency_icmp, ms);
                }
            }
        }
        pthread_rwlock_unlock(&cache_rwlock);
    }
    return NULL;
}

void* udp_server (void* data)
{
    int sock;
    int flags, sflags;
    struct sockaddr_in server_address;
    struct sockaddr_in client_address;

    uint64_t datagram_recieved[RECIEVED_SIZE];
    uint64_t datagram_sent[SEND_SIZE_2];
    socklen_t snda_len, rcva_len;
    ssize_t len, snd_len;

    // Creating IPv4 UDP socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0)
        syserr("socket");
    // After socket() call; we should close(sock) on any execution path;
    // Since all execution paths exit immediately, sock would be closed when 
    // program terminates.

    // IPv4
    server_address.sin_family = AF_INET; 
    // Listening on all interfaces
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    // Port for receiving is PORT_NUM
    server_address.sin_port = htons(UDP_PORT_NUM);

    // Bind the socket to a concrete address
    if (bind(sock, (struct sockaddr *) &server_address,
            (socklen_t) sizeof(server_address)) < 0)
        syserr("bind");

    printf("Started udp server\n");
    snda_len = (socklen_t) sizeof(client_address);
    for(;;)
    {
        // Recieving the datagram.
        rcva_len = (socklen_t) sizeof(client_address);
        flags = 0;

        len = recvfrom(sock, datagram_recieved, sizeof(datagram_recieved), 
            flags, (struct sockaddr *) &client_address, &rcva_len);
        if (len < 0)
            syserr("error on datagram from client socket");
        else 
        {
            // Sending the response datagram.
            sflags = 0;
            uint64_t current = GetTimeStamp();
            len = sizeof(datagram_sent);
            datagram_sent[0] = datagram_recieved[0];
            datagram_sent[1] = htobe64(current);
            snd_len = sendto(sock, datagram_sent, (size_t) len, sflags,
                    (struct sockaddr *) &client_address, snda_len);
            if (snd_len != len)
                syserr("error on sending datagram to client socket");

        }
    }
    return NULL;
}


void* update_cache(void* data)
{

    // Wait and measure - we are removing entries for services
    // that have not replied 10 times and more.
    printf("Started updating cache\n");
    for (;;)
    {
        sleep(MDNS_UPDATE_RATE);
        mdns_cache_remove_old_entries ();
    }
    return NULL;
}



// This thread will handle connection to telnet - it will read and answer, write
// every 1 second and send beeps.
void *telnet_handle_connection (void *sock_ptr) {
    int sock;
    int ret;
    socklen_t len;
    char peername[LINE_SIZE + 1], peeraddr[LINE_SIZE + 1];
    struct sockaddr_in addr;

    sock = *(int *)sock_ptr;
    free(sock_ptr);

    struct timeval timeout;      
    timeout.tv_sec = INTERFACE_UPDATE;
    timeout.tv_usec = 0;

    if (setsockopt (sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
                sizeof(timeout)) < 0)
        syserr("setsockopt failed\n");

    if (setsockopt (sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
                sizeof(timeout)) < 0)
        syserr("setsockopt failed\n");


    len = sizeof(addr);
    // Getting the address
    ret = getpeername(sock, (struct sockaddr *)&addr, &len);
    if (ret == -1) 
    {
        perror("getsockname");
        exit(1);
    }

    inet_ntop(AF_INET, &addr.sin_addr, peeraddr, LINE_SIZE);
    snprintf(peername, LINE_SIZE, "%s:%d", peeraddr, ntohs(addr.sin_port));

    printf("%s telnet connection open (handled by thread %lu, pid is %d)\n",
        peername, (unsigned long)pthread_self(), getpid());

    int client_num = get_telnet_client_num();


    int rv;

    rv = write_to_ui(line_nums[client_num], sock);
    if (rv < 0)
    {
        free_telnet_client_num(client_num);
        close(sock);
        return NULL;
    }
    for (;;)
    {
        rv = handle_telnet(sock, client_num, 0);
        if (rv == TELNET_END)
        {
            break;
        }
    }
    printf("Telnet connection to %s closed\n", peername);
    free_telnet_client_num(client_num);
    close(sock);
    return NULL;
}

// This will accept any incoming telnet connection and create new thread to
// to handle it.
void* run_telnet_server (void* ptr)
{
    int sock, rc;
    int msgsock;
    int *msgsock_for_thread;

    struct sockaddr_in server;

    printf("Telnet\n");
    // Creating socket
    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock == -1) 
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }


    // Binding the socket to the port.
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(TELNET_PORT_NUM);

    rc = bind(sock, (struct sockaddr *)&server, sizeof(server));
    if (rc == -1) 
    {
        perror("bind");
        exit(1);
    }

    rc = listen(sock, 5);
    if (rc == -1) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    // Main loop for accepting connections.
    for (;;) 
    {

        pthread_t t;
        msgsock = accept(sock, (struct sockaddr *)NULL, NULL);
        if (msgsock == -1) 
        {
            perror("accept");
            exit(EXIT_FAILURE);
        }
        // Only for this thread, passing msgsock.
        msgsock_for_thread = malloc(sizeof(int));
        if (!msgsock_for_thread) 
        {
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        *msgsock_for_thread = msgsock;

        rc = pthread_create(&t, 0, telnet_handle_connection, 
            msgsock_for_thread);
        if (rc == -1) 
        {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
        // Detaching the thread.
        rc = pthread_detach(t);
        if (rc == -1) 
        {
            perror("pthread_detach");
            exit(EXIT_FAILURE);
        }
    }
    return NULL;
}



// Asks for every services of OPOZNIENIE
void* querymdns(void* sock_ptr)
{
    int* sockt = (int*) sock_ptr;
    int sock = *sockt;
    printf("Started quering\n");
    for (;;) 
    {
        
        mdns_send_query(sock, SERVICE_NAME_UDP, RRTYPE_PTR);
        mdns_send_query(sock, SERVICE_NAME_TCP, RRTYPE_PTR);
        //pthread_rwlock_rdlock(&cache_rwlock);
        //mdns_cache_print();
        //pthread_rwlock_unlock(&cache_rwlock);
        sleep(MDNS_UPDATE_RATE);
    }
    return NULL;
}


// Advertises our services (sending PTR and A)
void* advertisemdns_udp(void* sock_ptr)
{
    int* sockt = (int*) sock_ptr;
    int sock = *sockt;
    printf("Started advertising\n");
    for (;;) 
    {
        mdns_send_PTR(sock, SERVICE_NAME_UDP, MDNS_DOMAIN_UDP);
        mdns_send_A(sock, MDNS_DOMAIN_UDP, MDNS_IP);
        sleep(MDNS_UPDATE_RATE);
    }
    return NULL;
}

// Advertises our services (sending PTR and A)
void* advertisemdns_tcp(void* sock_ptr)
{
    int* sockt = (int*) sock_ptr;
    int sock = *sockt;
    printf("Started advertising\n");
    for (;;) 
    {
        mdns_send_PTR(sock, SERVICE_NAME_TCP, MDNS_DOMAIN_TCP);
        mdns_send_A(sock, MDNS_DOMAIN_TCP, MDNS_IP);
        sleep(MDNS_UPDATE_RATE);
    }
    return NULL;
}

// Read all incoming messages and reply to them
void* recvmdns(void* sock_ptr)
{
    int* sockt = (int*) sock_ptr;
    int sock = *sockt;
    mDNSPacket* mdns;
    printf("Started reading\n");
    for (;;) 
    {
        mdns = mdns_read_packet(sock);
        free_mDNSPacket(mdns);
    }
    return NULL;
}

/*int handle_input_setting (char* option, char* value)
{
    if ((value == NULL) && (option != NULL))
    {
        // USE TCP
        if (strcmp(option, USE_TCP_OPTION) == 0)
        {
            USE_TCP = 1;
        }
        else
        {
            return -1;
        }
    }
    else if ((value != NULL) && (option != NULL))
    {
        // UDP PORT
        if (strcmp(option, UDP_OPTION) == 0)
        {
            UDP_PORT_NUM = atoi(value);
        }
        // TELNET PORT
        else if (strcmp(option, TELNET_PORT_OPTION) == 0)
        {
            TELNET_PORT_NUM = atoi(value);
        }
        // HOW MANY TIMES WE MEASURE LATENCIES
        else if (strcmp(option, LATENCY_MEASURE_OPTION) == 0)
        {
            MDNS_LATENCY_RATE = atof(value);
        }
        else if (strcmp(option, COMPUTER_SCAN_OPTION) == 0)
        {
            MDNS_UPDATE_RATE = atoi(value);
        }
        // HOW MANY TIMES WE UPDATE THE TELNET INTERFACE
        else if (strcmp(option, INTERFACE_UPDATE_OPTION) == 0)
        {
            INTERFACE_UPDATE = atof(value);
        }
        else
        {
            return -1;
        }
    }
    return 0;
}*/



void print_error()
{
    syserr("Usage: [-u port_num] [-U port_num] [-t rate] [-T rate] [-v rate] [-s]...\n");
    exit(-1);
}

int main (int argc, char *argv[])
{

    if (argc > 1)
    {
        int i = 1;
        while (i < argc)
        {
            if (strcmp(argv[i], UDP_OPTION) == 0)
            {
                UDP_PORT_NUM = atoi(argv[(++i)]);
                printf("Set udp port to: %d\n", UDP_PORT_NUM);
            }
            else if (strcmp(argv[i], TELNET_PORT_OPTION) == 0)
            {
                TELNET_PORT_NUM = atoi(argv[(++i)]);
                printf("Set telnet port to: %d\n", TELNET_PORT_NUM);
            }
            else if (strcmp(argv[i], LATENCY_MEASURE_OPTION) == 0)
            {
                MDNS_LATENCY_RATE = atof(argv[(++i)]);
                printf("Set mdns latency rate to: %f\n", MDNS_LATENCY_RATE);
            }
            else if (strcmp(argv[i], COMPUTER_SCAN_OPTION) == 0)
            {
                MDNS_UPDATE_RATE = atoi(argv[(++i)]);
                printf("Set mdns update rate to: %d\n", MDNS_UPDATE_RATE);
            }
            else if (strcmp(argv[i], INTERFACE_UPDATE_OPTION) == 0)
            {
                INTERFACE_UPDATE = atof(argv[(++i)]);
                printf("Set interface update rate to: %f\n", INTERFACE_UPDATE);
            }
            else if (strcmp(argv[i], USE_TCP_OPTION) == 0)
            {
                USE_TCP = 1;
                printf("Set tcp: on\n");
            }
            else
            {
                print_error();
                break;
            }
            i++;
        }
    }
    // else default everything


    // Init the cache.
    mdns_cache_init();

    // Init latencies structure
    init_latencies();

    // Socket fd
    int sock;

    // Creates new socket.
    sock = mdns_init();
    init_mdns_ip();
    // Inits our domain name.
    init_mdns_domain(sock);



    int rc;

    // Creating the thread for telnet_server.
    pthread_t telnet_server;
    rc = pthread_create(&telnet_server, 0, run_telnet_server, NULL);
    if (rc < 0)
        syserr("pthread_create");
    rc = pthread_detach(telnet_server);
    if (rc < 0)
        syserr("pthread_detach");


    // The threads for handling mDNS.
    pthread_t mdns_query;
    pthread_t mdns_adv;
    pthread_t mdns_reciever;

    int* msgsock_for_thread;
    msgsock_for_thread = malloc(sizeof(int));
    if (!msgsock_for_thread) 
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    *msgsock_for_thread = sock;

    // Creating listener thread.
    rc = pthread_create(&mdns_reciever, 0, recvmdns, 
        ((void*) msgsock_for_thread));
    if (rc < 0)
        syserr("pthread_create");
    rc = pthread_detach(mdns_reciever);
    if (rc < 0)
        syserr("pthread_detach");

    msgsock_for_thread = malloc(sizeof(int));
    if (!msgsock_for_thread) 
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    *msgsock_for_thread = sock;

    // Creating asker thread.
    rc = pthread_create(&mdns_query, 0, querymdns, 
        ((void*) msgsock_for_thread));
    if (rc < 0)
        syserr("pthread_create");
    rc = pthread_detach(mdns_query);
    if (rc < 0)
        syserr("pthread_detach");


    msgsock_for_thread = malloc(sizeof(int));
    if (!msgsock_for_thread) 
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    *msgsock_for_thread = sock;

    // Creating advertiser thread.
    rc = pthread_create(&mdns_adv, 0, advertisemdns_udp, 
        ((void*) msgsock_for_thread));
    if (rc < 0)
        syserr("pthread_create");
    rc = pthread_detach(mdns_adv);
    if (rc < 0)
        syserr("pthread_detach");

    // IF WE USE TCP MEASUREMENT, CREATE NEW THREAD FOR IT.
    if (USE_TCP == 1)
    {
        pthread_t mdns_adv_tcp;
        msgsock_for_thread = malloc(sizeof(int));
        if (!msgsock_for_thread) 
        {
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        *msgsock_for_thread = sock;
        // Creating advertiser thread.
        rc = pthread_create(&mdns_adv_tcp, 0, advertisemdns_tcp, 
            ((void*) msgsock_for_thread));
        if (rc < 0)
            syserr("pthread_create");
        rc = pthread_detach(mdns_adv_tcp);
        if (rc < 0)
            syserr("pthread_detach");

    }

    pthread_t udp_serv;

    rc = pthread_create(&udp_serv, 0, udp_server, NULL);
    if (rc < 0)
        syserr("pthread_create");
    rc = pthread_detach(udp_serv);
    if (rc < 0)
        syserr("pthread_detach");  

    pthread_t measure_server;

    rc = pthread_create(&measure_server, 0, measure_latencies, NULL);
    if (rc < 0)
        syserr("pthread_create");
    rc = pthread_detach(measure_server);
    if (rc < 0)
        syserr("pthread_detach");
    
    pthread_t cache_updater;

    rc = pthread_create(&cache_updater, 0, update_cache, NULL);
    if (rc < 0)
        syserr("pthread_create");
    rc = pthread_detach(cache_updater);
    if (rc < 0)
        syserr("pthread_detach");
    
    // So that we will not end our process.
    for (;;)
    {

    }

    return 0;   
}