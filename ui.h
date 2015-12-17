#ifndef _UI_H_
#define _UI_H_

// This is the header for writing ui.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include "err.h"
#define MAX_COMPUTERS 10000
#define TERMINAL_WIDTH 81
#define TERMINAL_HEIGHT 24
#define BUFFER_SIZE 1000
#define UP_KEY "Q"
#define DOWN_KEY "A"
#define TELNET_END 1000

const char* CLEAR = "\033[2J\0";
const char* BEEP = "\a";

float INTERFACE_UPDATE = 1.0f; 

// The structure in which we will keep all the data about connection to an 
// address.
typedef struct
{
    // Address.
    char* addr_name;
    // Latencies in miliseconds.
    int udp;
    int tcp;
    int icmp;
    int isFree;

} latencyData;

// The array of all the connections data - for ui to access, and server
// to store.
latencyData latencies[MAX_COMPUTERS];
// How many ip's stored.
int latencies_size;
// If the data is sorted?
int is_sorted;

// In this array we will keep which telnet connection is in which line of ip's.
int line_nums[MAX_COMPUTERS];

// The lock for accessing latencies.
pthread_rwlock_t latency_rwlock;


// Inits client numbers.
int init_line_nums ()
{
    int i = 0;
    for (i = 0; i < MAX_COMPUTERS; i++)
    {
        line_nums[i] = -1;
    }
    return 0;
}

// Inits latencies.
int init_latencies()
{
    init_line_nums();
    int i = 0;
    for (i = 0; i < MAX_COMPUTERS; i++)
    {
        latencies[i].addr_name = NULL;
        latencies[i].udp = -1;
        latencies[i].tcp = -1;
        latencies[i].icmp = -1;
        latencies[i].isFree = 0;
        latencies_size = 0;
        is_sorted = 1;
    }
    pthread_rwlock_init(&latency_rwlock, NULL);
    return 0;
    
}

int free_latencies()
{
    pthread_rwlock_destroy(&latency_rwlock);
    return 0;
}



// Returns client number for holding which line is he displaying.
int get_telnet_client_num ()
{
    pthread_rwlock_wrlock(&latency_rwlock);
    int i = 0;
    while (i < MAX_COMPUTERS)
    {
        if (line_nums[i] == -1)
        {
            line_nums[i] = 0;
            pthread_rwlock_unlock(&latency_rwlock);
            return i;
        }
        else
            i++;
    }
    pthread_rwlock_unlock(&latency_rwlock);
    return -1;
}

// Frees the number which a telnet client holds for his display.
int free_telnet_client_num (int i)
{
    pthread_rwlock_wrlock(&latency_rwlock);
    line_nums[i] = -1;
    pthread_rwlock_unlock(&latency_rwlock);
    return 0;
}


// Sorting - decreasingly by avg latency.
int compare_latencies(const void *a,const void *b) {
    latencyData *x = (latencyData *) a;
    latencyData *y = (latencyData *) b;
    return ((y->udp + y->tcp + y->icmp)) - ((x->udp + x->tcp + x->icmp));
}

// Sort latencies - should be used on refresh and after adding new element.
// Through this we ensure that at least one of the packet latencies must be
// >= 0. So that we know that if we stop at packets == -1, then there are no
// packets left. That is how we calculate size of latencies.
int sort_latencies ()
{
    //pthread_rwlock_wrlock(&latency_rwlock);
    if (is_sorted == 0)
    {
        qsort(latencies, MAX_COMPUTERS, sizeof(latencyData), compare_latencies);
        is_sorted = 1;
    }
    //pthread_rwlock_unlock(&latency_rwlock);
    // else do nothing, is - sorted.
    return 0;
}


// Removes latency.
int remove_latency (int i)
{
    pthread_rwlock_wrlock(&latency_rwlock);
    latencies[i].isFree = 0;
    latencies[i].udp = -1;
    latencies[i].tcp = -1;
    latencies[i].icmp = -1;
    free(latencies[i].addr_name);
    latencies[i].addr_name = NULL;
    is_sorted = 0;
    latencies_size--;
    sort_latencies();
    pthread_rwlock_unlock(&latency_rwlock);
    return 0;
}

int find_latency(const char* addr_name)
{
    int i = 0;
    for (i = 0; i < MAX_COMPUTERS; i++)
    {
        if (latencies[i].addr_name != NULL)
        {
            if (strcmp(latencies[i].addr_name, addr_name) == 0)
            {
                return i;
            }
        }
    }
    return -1;
}

int remove_latency_name(const char* addr_name)
{
    pthread_rwlock_wrlock(&latency_rwlock);
    int spot = find_latency(addr_name);
    if ((spot != -1) && (spot < MAX_COMPUTERS))
    {
        latencies[spot].isFree = 0;
        latencies[spot].udp = -1;
        latencies[spot].tcp = -1;
        latencies[spot].icmp = -1;
        free(latencies[spot].addr_name);
        latencies[spot].addr_name = NULL;
        is_sorted = 0;
        latencies_size--;
        sort_latencies();
    }
    pthread_rwlock_unlock(&latency_rwlock);
    return 0;
}



// Inserts new ip to latencies.
// Addr_name MUST BE null terminated string.
int insert_latency (const char* addr_name, int udp, int tcp, int icmp)
{
    pthread_rwlock_wrlock(&latency_rwlock);
    int i = 0;
    i = find_latency(addr_name);
    if (i != -1)
    {
        if (udp > -1)
            latencies[i].udp = udp;
        if (tcp > -1)
            latencies[i].tcp = tcp;
        if (icmp > -1)
            latencies[i].icmp = icmp;
        is_sorted = 0;
        sort_latencies();
    }
    else
    {
        i = 0;
        // Looking for new place to store our ip, and it's content.
        while (i < MAX_COMPUTERS)
        {
            if (latencies[i].isFree == 0)
            {
                latencies[i].isFree = 1;
                latencies[i].addr_name = 
                    malloc((strlen(addr_name) + 1)  * sizeof(char));
                int j = 0;
                int size = strlen(addr_name);
                for (j = 0; j < size; j++)
                {
                    latencies[i].addr_name[j] = addr_name[j];
                }
                latencies[i].addr_name[size] = '\0';
                latencies[i].udp = udp;
                latencies[i].tcp = tcp;
                latencies[i].icmp = icmp;
                is_sorted = 0;
                latencies_size++;
                sort_latencies();
                pthread_rwlock_unlock(&latency_rwlock);
                return i;
            }
            else
            {
                i++;
            }
        }
    }

    pthread_rwlock_unlock(&latency_rwlock);
    // No place to store our new address.
    return -1;
}

// Returns first not empty latency from starting line.
int is_there_next_latency (int i)
{
    int j = i;
    while (j < MAX_COMPUTERS)
    {
        if ((latencies[j].udp == -1) && (latencies[i].tcp == -1) && 
            (latencies[i].icmp == -1) && (latencies[i].addr_name == NULL))
        {
            j++;
        }
        else
        {
            return 1;
        }
    }
    return 0;
}

char* latency_to_str (latencyData* dat)
{
    char* result = (char*) malloc(81 * sizeof(char));
    if (result == NULL)
        syserr("Malloc failed");
    if (dat->addr_name == NULL)
        syserr("Address cannot be NULL!");
    int addr_len = strlen(dat->addr_name);
    int i = 0;
    for (i = 0; i < addr_len; i++)
    {
        result[i] = dat->addr_name[i];
    }
    result[addr_len] = ' ';
    addr_len++;
    // now the latencies.
    char udp_str[20];
    int udp_len = sprintf(udp_str, "%d", dat->udp);
    char tcp_str[20];
    int tcp_len = sprintf(tcp_str, "%d", dat->tcp);
    char icmp_str[20];
    int icmp_len = sprintf(icmp_str, "%d", dat->icmp);
    // Now calculating the number of spaces
    int avg_lat = (dat->udp + dat->tcp + dat->icmp) / 3;
    int lat_len = udp_len + icmp_len + tcp_len + 3;
    if (lat_len + addr_len + avg_lat > 80)
    {
        // We probably could get % 80 latencies or simply max amount of spaces.
        // The latter is better in my opinion.
        int new_avg_len = 80 - addr_len - lat_len;
        for (i = addr_len; i < addr_len + new_avg_len; i++)
        {
            result[i] = ' ';
        }
        // Printing udp latencies.
        for (i = 0; i < udp_len; i++)
        {
            result[addr_len + new_avg_len + i] = udp_str[i];
        }
        result[addr_len + new_avg_len + udp_len] = ' ';
        // Printing tcp latencies.
        for (i = 0; i < tcp_len; i++)
        {
            result[addr_len + new_avg_len + udp_len + i + 1] = tcp_str[i];
        }
        result[addr_len + new_avg_len + udp_len + tcp_len + 1] = ' ';
        // Printing icmp latencies.
        for (i = 0; i < icmp_len; i++)
        {
            result[addr_len + new_avg_len + udp_len + tcp_len + i + 2] = 
                icmp_str[i];
        }
        result[addr_len + new_avg_len + udp_len + tcp_len + icmp_len + 2] = ' ';
    }
    else
    {
        for (i = addr_len; i < addr_len + avg_lat; i++)
        {
            result[i] = ' ';
        }
        // Printing udp latencies.
        for (i = 0; i < udp_len; i++)
        {
            result[addr_len + avg_lat + i] = udp_str[i];
        }
        result[addr_len + avg_lat + udp_len] = ' ';
        // Printing tcp latencies.
        for (i = 0; i < tcp_len; i++)
        {
            result[addr_len + avg_lat + udp_len + i + 1] = tcp_str[i];
        }
        result[addr_len + avg_lat + udp_len + tcp_len + 1] = ' ';
        // Printing icmp latencies.
        for (i = 0; i < icmp_len; i++)
        {
            result[addr_len + avg_lat + udp_len + tcp_len + i + 2] = 
                icmp_str[i];
        }
        result[addr_len + avg_lat + udp_len + tcp_len + icmp_len + 2] = ' ';
        for (i = addr_len + avg_lat + udp_len + tcp_len + icmp_len + 3; i < 80;
            i++)
        {
            result[i] = ' ';
        }
    }
    result[80] = '\n';

    return result;
}

// Clears the display.
int clear_display (int msg_sock)
{
    // Clearing the terminal.
    ssize_t len = strlen(CLEAR) + 1;
    ssize_t snd_len = send(msg_sock, CLEAR, len, MSG_NOSIGNAL);
    if (snd_len != len)
    {
        if (errno == EWOULDBLOCK)
        {
            errno = 0;
            return 0;
        }
        else
            return -1;
    }
        //syserr("writing to client socket");
    return 0;
}


// This function writes given reply.
int write_to_ui (int line, int msg_sock)
{
    
    // Now sending wanted ip's from given line.
    pthread_rwlock_rdlock(&latency_rwlock);
    clear_display(msg_sock);
    if (is_there_next_latency(line))
    {
        int i = 0;
        char* returned_array = (char*) malloc(((latencies_size - line) * 81 * 
            sizeof(char)) + 1);
        if (returned_array == NULL)
            syserr("malloc failed");
        int j = 0;
        for (i = line; i < latencies_size; i++)
        {
            char* handled_str = latency_to_str(&latencies[i]);
            for (j = 0; j <= 80; j++)
            {
                returned_array[((i - line) * 81) + j] = handled_str[j];
            }
            free(handled_str);
        }
        returned_array[(latencies_size - line) * 81] = '\0';
        ssize_t len = (((latencies_size - line) * 81 * 
            sizeof(char)) + 1);
        ssize_t snd_len = send(msg_sock, returned_array, len, MSG_NOSIGNAL);
        free(returned_array);
        if (snd_len != len)
        {
            pthread_rwlock_unlock(&latency_rwlock);
            if (errno == EWOULDBLOCK)
            {
                errno = 0;
                return 0;
            }
            else
                return -1;
        }
            //syserr("Writing to client socket");
    }
    pthread_rwlock_unlock(&latency_rwlock);
    // else we send nothing because there is no ip's left.
    return 0;
}

// This function sends beep when wrong input is given.
int send_beep (int msg_sock)
{
    // Clearing the terminal.
    ssize_t len = strlen(BEEP);
    ssize_t snd_len = send(msg_sock, BEEP, len, MSG_NOSIGNAL);
    if (snd_len != len)
    {   
        if (errno == EWOULDBLOCK)
        {
            errno = 0;
            return 0;
        }
        else
            return -1;
    }
        //syserr("writing to client socket");
    return 0;
}

// This function reads from socket and sends proper response.
// Probably this won't be so easy because we would probably need
// to iterate through whole string read in buffer.
int handle_telnet (int msg_sock, int client_num, int first)
{
    int res;
    if (first == 0)
    {
        char buffer[BUFFER_SIZE + 1];
        buffer[BUFFER_SIZE] = '\0';
        ssize_t len = recv(msg_sock, buffer, 
            sizeof(char) * (BUFFER_SIZE),  MSG_NOSIGNAL);
        if (len < 0)
        {
            if (errno == EWOULDBLOCK)
            {
                errno = 0;
                write_to_ui(line_nums[client_num], msg_sock);
            }
            else
            {
                return TELNET_END;
            }
            //syserr("reading from client socket");
            //return TELNET_END;
        }
        else if (len == 0)
        {
            return TELNET_END;
        }
        else
        {
            buffer[BUFFER_SIZE] = '\0';
            // Find if we recieved some good input.
            // Either we do only strcmp or we go through all input
            int i = 0;
            while (i < len)
            {
                if (buffer[i] == 'Q')
                {
                    if (strlen(buffer) == 1)
                    {
                        if (line_nums[client_num] > 0)
                        {
                            line_nums[client_num]--;
                        }
                    }
                    else
                    {
                        res = send_beep(msg_sock);
                        if (res < 0)
                        {
                            return TELNET_END;
                        }
                    }
                }
                else if (buffer[i] == 'A')
                {
                    if (strlen(buffer) == 1)
                    {
                        if (line_nums[client_num] < latencies_size - 1)
                        {
                            line_nums[client_num]++;
                        }
                    }
                    else
                    {
                        res = send_beep(msg_sock);
                        if (res < 0)
                        {
                            return TELNET_END;
                        }
                    }
                }
                else
                {
                    res = send_beep(msg_sock);
                    if (res < 0)
                    {
                        return TELNET_END;
                    }
                }
                i++;
            }
            res = write_to_ui(line_nums[client_num], msg_sock);
            if (res < 0)
            {
                return TELNET_END;
            }
        }
    }
    else
    {
        line_nums[client_num] = 0;
        res = write_to_ui(0, msg_sock);
        if (res < 0)
            return TELNET_END;
    }
    return 0;
}



#endif