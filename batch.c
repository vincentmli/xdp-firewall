// SPDX-License-Identifier: GPL-2.0                                              
                                                                                 
#include <arpa/inet.h>                                                           
#include <linux/bpf.h>                                                           
#include <netinet/in.h>                                                          
#include <stdio.h>                                                               
#include <errno.h>                                                               
#include <string.h>                                                              
#include <stdlib.h>                                                              
#include <unistd.h>                                                              
                                                                                 
#include "bpf/bpf.h"                                                            
#include "bpf/libbpf.h"                                                          
                                                                                 
                                                                                 
struct lpm_key {                                                            
        __u32 prefix;                                                            
        struct in_addr ipv4;                                                     
};                                                                               
                                                                                 
static void map_batch_update(int map_fd, __u32 max_entries,                      
                             struct lpm_key *keys, int *values)       
{                                                                                
        __u32 i;                                                                 
        int err;                                                                 
        char buff[16] = { 0 };                                                   
        DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,                            
                .elem_flags = 0,                                                 
                .flags = 0,                                                      
        );                                                                       
                                                                                 
        for (i = 0; i < max_entries; i++) {                                      
                keys[i].prefix = 32;                                             
                snprintf(buff, 16, "192.168.1.%d", i + 1);                       
                inet_pton(AF_INET, buff, &keys[i].ipv4);                         
                values[i] = i + 1;                                               
        }                                                                        
                                                                                 
        err = bpf_map_update_batch(map_fd, keys, values, &max_entries, &opts);   
}                                                                           

int main () {
}
