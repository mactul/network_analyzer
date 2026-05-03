/**
 * @file fuzzer.c
 * @author Macéo Tuloup
 * @brief This file is not compiled with the project, it's a replacement for main.c when compiling the fuzzer.
 * @version 1.0.0
 * @date 2024-12-14
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "listener.h"

static const char* random_name(char* name, size_t name_size, const uint8_t *seed, size_t seed_size)
{
    uint8_t reduced_seed[32] = {};
    for(size_t i = 0; i < seed_size; i++)
    {
        reduced_seed[i % sizeof(reduced_seed)] ^= seed[i];
    }

    static const char authorized_chars[] = "ABCDEFGHIJKLMOPQRSTUVWXYZabcdefghijklmopqrstuvwxyz0123456789";
    for(size_t i = 0; i < name_size - 1; i++)
    {
        uint8_t s = reduced_seed[i % sizeof(reduced_seed)];

        name[i] = authorized_chars[s % (sizeof(authorized_chars) - 1)];
    }
    name[name_size - 1]= '\0';

    return name;
}


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    char name[32];
    char path[256];

    static bool tmp_calculated = false;
    static char tmp_dir[512] = "/tmp/network_analyzer_fuzzer_run_dir_XXXXXX";

    if(!tmp_calculated)
    {
        tmp_calculated = mkdtemp(tmp_dir) != NULL;
        fclose(stdout);
    }

    snprintf(path, sizeof(path), "%s/%s.pcap", tmp_dir, random_name(name, sizeof(name), Data, Size));

    FILE* test_file = fopen(path, "wb");
    if (test_file == NULL)
    {
        return 1;
    }
    fwrite(Data, sizeof(uint8_t), Size, test_file);
    fclose(test_file);

    int ret_code = run_pcap(3, NULL, NULL, path);
    remove(path);

    return ret_code;
}