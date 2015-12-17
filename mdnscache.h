#ifndef _MDNSCACHE_H_
#define _MDNSCACHE_H_

// This is a header used for storing many defines and some variables
// for opoznienia.c.
/*#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/util.h>*/

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
#include <pthread.h>

#include "ui.h"
#include "err.h"

#define RPLY_COUNT 3

typedef struct _myString
{
    char* str;
    int32_t len;
} myString;

char* myString_free(myString* s, int32_t isDeleting)
{
    if (s != NULL)
    {
        
        if (isDeleting == 1)
        {
            if(s->str != NULL)
                free(s->str);
            free(s);
        }
        else
        {
            char* res = NULL;
            if(s->str != NULL)
            {
                res = malloc(s->len + 1);
                int i = 0;
                for (i = 0; i < s->len; i++)
                {
                    res[i] = s->str[i];
                }
                res[s->len] = '\0';
                free(s->str);
            }
            
            
            free(s);
            return res;
        }
    }
    return NULL;
}

myString* myString_new()
{
    myString* res;
    res = malloc(sizeof(myString));
    if (res == NULL)
        syserr("Malloc failed");
    res->str = malloc(1);
    res->str[0] = '\0';
    res->len = 0;
    return res;
}

myString* myString_append_char(myString* s, char c)
{
    if (s == NULL)
    {
        myString* res;
        res = malloc(sizeof(myString));
        res->str = malloc(1);
        res->len = 1;
        res->str[0] = c;
        s = res;
        return res;
    }
    if (s->len == 0)
    {
        if (s->str != NULL)
            free(s->str);
    }
    myString* res;
    res = malloc(sizeof(myString));
    res->str = malloc(sizeof(char) * ((s->len) + 1));
    res->len = s->len + 1;
    int i = 0;
    while(i < s->len)
    {
        res->str[i] = s->str[i];
        i++;
    }

    res->str[i] = c;

    myString_free(s, 1);
    s = res;
    return res;
}



myString* myString_append_string(myString* s,const char* data, uint8_t bytes)
{
    int i = 0;
    myString* res;
    res = malloc(sizeof(myString));
    if (s != NULL)
    {
        if (s->len == 0)
        {
            myString_free(s, 1);
            res->str = malloc(bytes);
            res->len = bytes;
            i = 0;
            while (i < (bytes))
            {
                res->str[i] = data[i];
                i++;
            }
            s = res;
            return res;
        }
        else
        {
            res->str = malloc(sizeof(char) * ((s->len) + (bytes)));
            res->len = s->len + (bytes);

            while (i < s->len)
            {
                res->str[i] = s->str[i];
                i++;
            }
            i = 0;
            while (i < (bytes))
            {
                res->str[i + s->len] = data[i];
                i++;
            }
            myString_free(s, 1);
            s = res;
            return res;
        }

    }
    else
    {
        res->str = malloc(bytes);
        res->len = bytes;
        i = 0;
        while (i < (bytes))
        {
            res->str[i] = data[i];
            i++;
        }
        s = res;
        return res;
    }
}



typedef struct _mDNSCache
{
    // The name of the service
    char* service_name;
    // The ip address of the service.
    unsigned char* ip;
    // Length of the service name
    int32_t len;
    // How many times we have not gone reply from last time.
    int32_t times_rply;
    int32_t has_tcp;
} mDNSCacheNode;

#define MAX_CACHE_SIZE 32768


// All operations on cache should be locked.

// The cache for all the services.
mDNSCacheNode* mDNSCache[MAX_CACHE_SIZE];

// The lock for accessing cache
pthread_rwlock_t cache_rwlock;


// Inits the cache with the NULL
void mdns_cache_init ()
{
    printf("Inicjalizuje cache\n");
    int i = 0;
    for (i = 0; i < MAX_CACHE_SIZE; i++)
    {
        mDNSCache[i] = NULL;
    }
    pthread_rwlock_init(&cache_rwlock, NULL);
}

// Called on ending.
void mdns_cache_free ()
{
    int i;
    for (i = 0; i < MAX_CACHE_SIZE; i++)
    {
        if (mDNSCache[i] != NULL)
        {
            if (mDNSCache[i]->service_name != NULL)
            {
                free(mDNSCache[i]->service_name);
            }
            if (mDNSCache[i]->ip != NULL)
            {
                free(mDNSCache[i]->ip);
            }
            free(mDNSCache[i]);
        }
        mDNSCache[i] = NULL;
    }
    pthread_rwlock_destroy(&cache_rwlock);
}

int32_t mdns_cache_find (const char* name)
{
    //pthread_rwlock_rdlock(&cache_rwlock);
    int i = 0;
    for (i = 0; i < MAX_CACHE_SIZE; i++)
    {
        if (mDNSCache[i] != NULL)
        {
            if (strcmp(mDNSCache[i]->service_name, name) == 0)
            {
                // Return the current position.
                //pthread_rwlock_unlock(&cache_rwlock);
                return i;
            }
        }
    }
    //pthread_rwlock_unlock(&cache_rwlock);
    // No such entry.
    return -1;
}

// Finds first empty spot in the cache.
int32_t mdns_cache_find_free ()
{
    int i = 0;
    while (i < MAX_CACHE_SIZE)
    {
        if (mDNSCache[i] == NULL)
        {
            return i;
        }
        i++;
    }
    // No spot.
    return -1;
}

// Add to cache
void mdns_cache_add (const char* name,  unsigned char* ip, int32_t has_tcp)
{
    pthread_rwlock_wrlock(&cache_rwlock);
    int spot;
    // Now find the place, maybe it already is.
    if ((spot = mdns_cache_find(name)) == -1)
    {
        // Create new node.
        mDNSCacheNode* node;
        node = malloc(sizeof(mDNSCacheNode));
        if (node == NULL)
            syserr("Malloc has failed");

        node->service_name = strdup(name);
        node->len = strlen(name);
        if (ip != NULL)
        {
            node->ip = malloc(4);
            memcpy(node->ip, ip, 4);
        }
        else
            node->ip = NULL;
        node->times_rply = 0;
        node->has_tcp = has_tcp;

        // Insert at first free spot.
        int32_t spot = mdns_cache_find_free();
        if (spot == -1)
        {
            // No spot, discard.
            if (node->ip != NULL)
                free(node->ip);
            free(node->service_name);
            free(node);
            pthread_rwlock_unlock(&cache_rwlock);
            return;
        }
        mDNSCache[spot] = node;
        pthread_rwlock_unlock(&cache_rwlock);
        return;
    }
    else
    {
        // Update if necessary.
        if (has_tcp == 1)
        {
            mDNSCache[spot]->has_tcp = 1;
        }
        mDNSCache[spot]->times_rply = 0;
    }
    pthread_rwlock_unlock(&cache_rwlock);
}

// Sets the ip of a mdns_cache or creates new if not exists.
void mdns_cache_add_ip (const char* name, unsigned char* ip, int32_t has_tcp)
{
    pthread_rwlock_wrlock(&cache_rwlock);
    int spot = 0;
    if ((spot = mdns_cache_find(name)) == -1)
    {
        // Create new node.
        mDNSCacheNode* node;
        node = malloc(sizeof(mDNSCacheNode));
        if (node == NULL)
            syserr("Malloc has failed");

        node->service_name = strdup(name);
        node->len = strlen(name);
        
        if (ip != NULL)
        {
            node->ip = malloc(4);
            memcpy(node->ip, ip, 4);
        }
        else
            node->ip = NULL;
        node->times_rply = 0;
        node->has_tcp = has_tcp;

        // Insert at first free spot.
        int32_t spot = mdns_cache_find_free();
        if (spot == -1)
        {
            // No spot, discard.
            if (node->ip != NULL)
                free(node->ip);
            free(node->service_name);
            free(node);
            pthread_rwlock_unlock(&cache_rwlock);
            return;
        }
        mDNSCache[spot] = node;
        pthread_rwlock_unlock(&cache_rwlock);
        return;
    }
    else
    {
        if (mDNSCache[spot]->ip == NULL)
        {
            mDNSCache[spot]->ip = malloc(4);
        }
        memcpy(mDNSCache[spot]->ip, ip, 4);
        mDNSCache[spot]->times_rply = 0;
        if (has_tcp == 1)
        {
            mDNSCache[spot]->has_tcp = has_tcp;
        }
    }
    pthread_rwlock_unlock(&cache_rwlock);
}


// Free the node
void mdns_cache_free_node (mDNSCacheNode* node)
{
    if (node != NULL)
    {
        if (node->service_name != NULL)
        {
            free(node->service_name);
        }
        if (node->ip != NULL)
        {
            free(node->ip);
        }
        free(node);
        node = NULL;
    }
}


// Removes a spot in cache with this name
void mdns_cache_remove (const char* name)
{
    int32_t spot = mdns_cache_find(name);
    if (spot != -1)
    {
        if (mDNSCache[spot]->ip != NULL)
            free(mDNSCache[spot]->ip);
        if (mDNSCache[spot]->service_name != NULL)
            free(mDNSCache[spot]->service_name);
        free(mDNSCache[spot]);
        // Now let's null that thing down!
        mDNSCache[spot] = NULL;
    }
}

// Remove all from the cache
void mdns_cache_clear ()
{
    pthread_rwlock_wrlock(&cache_rwlock);
    int i = 0;
    for (i = 0; i < MAX_CACHE_SIZE; i++)
    {
        mdns_cache_free_node(mDNSCache[i]);
    }
    pthread_rwlock_unlock(&cache_rwlock);
}


// Remove those entries which have not replied to the last 10 calls.
void mdns_cache_remove_old_entries ()
{
    pthread_rwlock_wrlock(&cache_rwlock);
    int i = 0;
    for (i = 0; i < MAX_CACHE_SIZE; i++)
    {
        if (mDNSCache[i] != NULL)
        {
            if (mDNSCache[i]->times_rply > RPLY_COUNT)
            {
                myString* s;
                char* host_name;

                s = myString_new();
                char ip1[5];
                sprintf(ip1, "%d", mDNSCache[i]->ip[0]);

                s = myString_append_string(s, ip1, strlen(ip1));
                s = myString_append_char(s, '.');
                char ip2[5];
                sprintf(ip2, "%d", mDNSCache[i]->ip[1]);
                s = myString_append_string(s, ip2, strlen(ip2));
                s = myString_append_char(s, '.');
                char ip3[5];
                sprintf(ip3, "%d", mDNSCache[i]->ip[2]);
                s = myString_append_string(s, ip3, strlen(ip3));
                s = myString_append_char(s, '.');
                char ip4[5];
                sprintf(ip4, "%d", mDNSCache[i]->ip[3]);
                s = myString_append_string(s, ip4, strlen(ip4));

                host_name = myString_free(s, 0);
                //printf("Usuwam %s\n", host_name);
                remove_latency_name(host_name);
                //sort_latencies();
                mdns_cache_free_node(mDNSCache[i]);
                free(host_name);
                mDNSCache[i] = NULL;
            }
        }
    }
    pthread_rwlock_unlock(&cache_rwlock);
}

void mdns_cache_print ()
{
    pthread_rwlock_rdlock(&cache_rwlock);
    int i = 0;
    while (i < MAX_CACHE_SIZE)
    {
        if (mDNSCache[i] != NULL)
        {

            if ((mDNSCache[i]->ip != NULL) && 
                (mDNSCache[i]->service_name != NULL))
            {
                printf("%s %d.%d.%d.%d", mDNSCache[i]->service_name, 
                mDNSCache[i]->ip[0], mDNSCache[i]->ip[1], mDNSCache[i]->ip[2],
                mDNSCache[i]->ip[3]);
                if (mDNSCache[i]->has_tcp == 1)
                    printf(" TCP\n");
                else
                    printf(" UDP\n");
            }
        }
        i++;
    }
    pthread_rwlock_unlock(&cache_rwlock);
    //printf("Tutaj jest print\n");    
}

#endif