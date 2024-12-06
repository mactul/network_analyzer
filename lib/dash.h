/*
Copyright 2024 Valentin Foulon

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef DASH_H
#define DASH_H

#include <stdbool.h>
#include <stddef.h>


typedef struct {
    char opt_name;
    bool allow_flag_unset;
    bool param_optional;
    const char* param_name;
    const char* longopt_name;
    const char* description;
    void* user_pointer;
} dash_Longopt;

bool dash_arg_parser(int* argc, char* argv[], dash_Longopt* options);
void dash_print_usage(const char* argv0, const char* header, const char* footer, const char* required_arguments[], const dash_Longopt* options, FILE* output_file);
void dash_print_summary(int argc, char** argv, const dash_Longopt* options, FILE* output_file);
void dash_free(dash_Longopt* options);

#endif
