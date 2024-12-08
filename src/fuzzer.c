#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "listener.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    FILE* test_file = fopen("./fuzzed.cap", "wb");
    if (test_file == NULL)
    {
        return 1;
    }
    fwrite(Data, sizeof(uint8_t), Size, test_file);
    fclose(test_file);

    return run_pcap(3, NULL, NULL, "./fuzzed.cap");
}