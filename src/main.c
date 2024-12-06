#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#include "common.h"
#include "ip_display.h"
#include "dns_display.h"
#include "dhcp_display.h"
#include "ethernet_display.h"
#include "transport_display.h"

#include "lib/dash.h"

#define MAX_INTERFACE_NAME 256
#define MAX_INT_STR_SIZE 8

typedef struct {
    char* interface;
    char* offline;
    char* filter;
    char* verbosity;
    bool help;
} Arguments;

static char _errbuf[PCAP_ERRBUF_SIZE];

void select_interface(char* buffer, unsigned int buffer_size)
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
        printf("\033[H\033[2J");
        while(current_interface != NULL)
        {
            counter++;
            printf("%d: %s\n", counter, current_interface->name);
            current_interface = current_interface->next;
        }
        printf("Select an interface (1-%d): ", counter);
        fgets(str, MAX_INT_STR_SIZE, stdin);
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



void callback(unsigned char* user __attribute__((unused)), const struct pcap_pkthdr* header, const unsigned char* bytes)
{
    uint8_t protocol;
    uint16_t dest_port = 0;
    uint16_t src_port = 0;
    const unsigned char* left_bytes = bytes;
    left_bytes = display_ethernet_frame(left_bytes);
    left_bytes = display_ip(left_bytes, &protocol);
    if(protocol == 0x11)
    {
        left_bytes = display_udp(left_bytes, &dest_port, &src_port);
    }
    else if(protocol == 0x06)
    {
        left_bytes = display_tcp(left_bytes, &dest_port, &src_port);
    }

    if(dest_port == 67 || dest_port == 68 || src_port == 67 || src_port == 68)
    {
        left_bytes = display_dhcp(left_bytes);
    }
    else if(dest_port == 53 || src_port == 53)
    {
        left_bytes = display_dns(left_bytes);
    }
    printf("Data:\n");
    display_generic_bytes(left_bytes, (int)header->caplen - (int)(left_bytes - bytes), 1);
    putchar('\n');
}


static void print_help(const char* program_name, const dash_Longopt* options, FILE* output_file)
{
    dash_print_usage(program_name, "my_wireshark, version 0.0.1", "", NULL, options, output_file);
}

int main(int argc, char* argv[])
{
    int r;
    int return_code = 1;

    Arguments arguments;

    dash_Longopt options[] = {
        {.user_pointer = &(arguments.help), .longopt_name="help", .opt_name='h', .description = "Display this help"},
        {.user_pointer = &(arguments.interface), .longopt_name = "interface", .opt_name = 'i', .param_name = "interface", .description = "Listen on $ (if unset, trigger a prompt)"},
        {.user_pointer = &(arguments.filter), .longopt_name = "filter", .opt_name = 'f', .param_name = "filter", .description = "A pcap $ to only get some packets."},
        {.user_pointer = &(arguments.offline), .longopt_name = "offline", .opt_name = 'o', .param_name = "file", .description = "An input $ that can be used instead of sniffing the network"},
        {.user_pointer = &(arguments.verbosity), .longopt_name = "verbosity", .opt_name = 'v', .param_name = "level", .description = "Set the verbosity to $, authorized levels are 1, 2 or 3"},
        {.user_pointer = NULL}
    };

    if (!dash_arg_parser(&argc, argv, options))
    {
        fputs("Invalid arguments\n", stderr);
        print_help(argv[0], options, stderr);
        return 1;
    }

    if(arguments.help)
    {
        print_help(argv[0], options, stdout);
        return 0;
    }

    pcap_t* interface = NULL;
    char interface_name[MAX_INTERFACE_NAME];

    pcap_init(PCAP_CHAR_ENC_UTF_8, _errbuf);

    select_interface(interface_name, MAX_INTERFACE_NAME);

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

    printf("start capture\n");

    pcap_loop(interface, -1, callback, NULL);

    return_code = 0;
CLOSE:
    if(interface != NULL)
    {
        pcap_close(interface);
        interface = NULL;
    }

    return return_code;
}