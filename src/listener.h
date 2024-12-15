#ifndef LISTENER_H
#define LISTENER_H


/**
 * @brief Start a capture and then passes each packet to the decapsulation function in decapsulation.c
 * 
 * @param verbosity A number between 1 and 3
 * @param interface_name The name of the network interface to listen on, if NULL and if offline_filename is NULL, a menu will appear to select this interface.
 * @param filter A pcap filter string, NULL to disable all filters.
 * @param offline_filename A filepath to a pcap file that can be parsed offline, NULL to disable offline parsing.
 * @return - 0 if all was read without any error, else `1`
 */
int run_pcap(int verbosity, char* interface_name, char* filter, char* offline_filename);

#endif