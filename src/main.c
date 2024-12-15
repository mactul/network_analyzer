/**
 * @file main.c
 * @author Macéo Tuloup
 * @brief This file is the entry point of the program, its goal is to parse the command line and then call run_pcap
 * @version 1.0.0
 * @date 2024-12-14
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#include <stdio.h>
#include <stdlib.h>

#include "listener.h"
#include "lib/dash.h"

typedef struct {
    char* interface;
    char* offline;
    char* filter;
    char* verbosity;
    bool help;
} Arguments;


static void print_help(const char* program_name, const dash_Longopt* options, FILE* output_file)
{
    dash_print_usage(program_name, "my_wireshark, version 1.0.0", "", NULL, options, output_file);
}


int main(int argc, char* argv[])
{
    int verbosity = 3;
    int return_code = 1;

    Arguments arguments;

    dash_Longopt options[] = {
        {.user_pointer = &(arguments.help), .longopt_name="help", .opt_name='h', .description = "Display this help"},
        {.user_pointer = &(arguments.interface), .longopt_name = "interface", .opt_name = 'i', .param_name = "interface", .description = "Listen on $ (if unset, trigger a prompt)"},
        {.user_pointer = &(arguments.filter), .longopt_name = "filter", .opt_name = 'f', .param_name = "filter", .description = "A pcap $ to only get some packets."},
        {.user_pointer = &(arguments.offline), .longopt_name = "offline", .opt_name = 'o', .param_name = "file", .description = "An input $ that can be used instead of sniffing the network"},
        {.user_pointer = &(arguments.verbosity), .longopt_name = "verbosity", .opt_name = 'v', .param_name = "level", .description = "Set the verbosity to $, authorized levels are 1, 2 or 3 (default: 3)"},
        {.user_pointer = NULL}
    };

    if (!dash_arg_parser(&argc, argv, options))
    {
        fputs("Invalid arguments\n", stderr);
        print_help(argv[0], options, stderr);
        goto END;
    }

    if(arguments.help)
    {
        print_help(argv[0], options, stdout);
        return_code = 0;
        goto END;
    }

    if(arguments.verbosity != NULL)
    {
        verbosity = atoi(arguments.verbosity);
        if(verbosity != 1 && verbosity != 2 && verbosity != 3)
        {
            fputs("Invalid verbosity\n", stderr);
            print_help(argv[0], options, stderr);
            goto END;
        }
    }

    return_code = run_pcap(verbosity, arguments.interface, arguments.filter, arguments.offline);

END:
    dash_free(options);
    return return_code;
}