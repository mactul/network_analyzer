#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#include "decapsulation.h"
#include "listener.h"

#define MAX_INTERFACE_NAME 256
#define MAX_INT_STR_SIZE 8

static char _errbuf[PCAP_ERRBUF_SIZE];

static void select_interface(char* buffer, unsigned int buffer_size)
{
    int answer = 0;
    pcap_if_t* interfaces_list_root;
    pcap_if_t* current_interface;

    if(pcap_findalldevs(&interfaces_list_root, _errbuf))
    {
        fprintf(stderr, "%s\n", _errbuf);
        exit(EXIT_FAILURE);
    }

    if(interfaces_list_root == NULL)
    {
        fprintf(stderr, "There is no interface that can be analyzed\nMaybe try running this program as root\n");
        exit(EXIT_FAILURE);
    }

    while(answer == 0)
    {
        int counter = 0;
        char str[MAX_INT_STR_SIZE];
        current_interface = interfaces_list_root;
        while(current_interface != NULL)
        {
            counter++;
            printf("%d: %s\n", counter, current_interface->name);
            current_interface = current_interface->next;
        }
        printf("Select an interface (1-%d): ", counter);
        if(fgets(str, MAX_INT_STR_SIZE, stdin) == NULL)
        {
            putchar('\n');
            fprintf(stderr, "End of file on stdin and the interface wasn't specified\n");
            exit(EXIT_FAILURE);
        }
        answer = atoi(str);
        if(answer > counter)
        {
            answer = 0;
        }
    }

    current_interface = interfaces_list_root;
    for(int i = 1; i < answer; i++)
    {
        current_interface = current_interface->next;
    }

    strncpy(buffer, current_interface->name, buffer_size-1);
    buffer[buffer_size-1] = '\0';

    pcap_freealldevs(interfaces_list_root);
    interfaces_list_root = NULL;
    current_interface = NULL;
}



static void callback(u_char* user, const struct pcap_pkthdr* header, const unsigned char* bytes)
{
    decapsulation(bytes, bytes + header->caplen, (int)((size_t)user));
}


int run_pcap(int verbosity, char* interface_name, char* filter, char* offline_filename)
{
    int r;
    int return_code = 1;
    pcap_t* interface = NULL;
    char interface_buffer[MAX_INTERFACE_NAME];

    pcap_init(PCAP_CHAR_ENC_UTF_8, _errbuf);

    if(offline_filename != NULL)
    {
        if((interface = pcap_open_offline(offline_filename, _errbuf)) == NULL)
        {
            fprintf(stderr, "%s\n", _errbuf);
            goto CLOSE;
        }
    }
    else
    {
        if(interface_name == NULL)
        {
            interface_name = interface_buffer;
            select_interface(interface_name, MAX_INTERFACE_NAME);
        }

        printf("Scanning interface: %s\n", interface_name);

        if((interface = pcap_create(interface_name, _errbuf)) == NULL)
        {
            fprintf(stderr, "%s\n", _errbuf);
            goto CLOSE;
        }

        pcap_set_immediate_mode(interface, 1);
        pcap_set_promisc(interface, 1);

        if((r = pcap_activate(interface)))
        {
            if(r < 0)
            {
                pcap_perror(interface, "Activation error: ");
                goto CLOSE;
            }
            else
            {
                pcap_perror(interface, "Activation warning: ");
            }
        }
    }

    if(filter != NULL)
    {
        struct bpf_program compiled_filter;
        bpf_u_int32 ip, mask;
        if(pcap_lookupnet(interface_name, &ip, &mask, _errbuf))
        {
            fprintf(stderr, "%s\n", _errbuf);
            goto CLOSE;
        }
        if(pcap_compile(interface, &compiled_filter, filter, 0, mask))
        {
            pcap_perror(interface, "Filter compilation error: ");
            goto CLOSE;
        }
        if(pcap_setfilter(interface, &compiled_filter))
        {
            pcap_perror(interface, "Filter can't be set: ");
            goto CLOSE;
        }
    }

    printf("Starting Capture\n\n");

    pcap_loop(interface, -1, callback, (u_char*)((size_t)verbosity));

    return_code = 0;
CLOSE:
    if(interface != NULL)
    {
        pcap_close(interface);
        interface = NULL;
    }

    return return_code;
}