/*
Copyright 2024 Valentin Foulon

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#if defined(_WIN32) || defined(WIN32)
    #include <windows.h>
#endif

#include "dash.h"

enum COLORS {
    COLOR_BLUE,
    COLOR_RED,
    COLOR_GREEN
};

static void print_in_color(FILE* output, const char* str, enum COLORS color)
{
    #if defined(_WIN32) || defined(WIN32)
        static HANDLE  hConsole = NULL;
        WORD windows_color_code;
        switch(color)
        {
            case COLOR_BLUE:
                windows_color_code = FOREGROUND_BLUE;
                break;
            case COLOR_RED:
                windows_color_code = FOREGROUND_RED;
                break;
            case COLOR_GREEN:
                windows_color_code = FOREGROUND_GREEN;
                break;
            default:
                windows_color_code = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED;
                break;
        }

        if(hConsole == NULL)
            hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hConsole, windows_color_code);
        fprintf(output, "%s", str);
        SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED);
    #else
        int linux_color_code;
        switch(color)
        {
            case COLOR_BLUE:
                linux_color_code = 34;
                break;
            case COLOR_RED:
                linux_color_code = 31;
                break;
            case COLOR_GREEN:
                linux_color_code = 32;
                break;
            default:
                linux_color_code = 0;
                break;
        }
        fprintf(output, "\033[%dm%s\033[0m", linux_color_code, str);
    #endif
}

static size_t calculate_print_spacing(const dash_Longopt* options)
{
    // Calculate the number of spaces to align descriptions
    size_t max_length = 0;
    for (int i = 0; options[i].opt_name != '\0' || options[i].longopt_name != NULL; i++)
    {
        size_t length = 0;
        if (options[i].opt_name != '\0' && options[i].longopt_name != NULL)
        {
            length += 2;
            // Comma between shortopt and longopt
        }
        if (options[i].opt_name != '\0')
        {
            length += 2;
            // If there is a shortopt
            if (options[i].allow_flag_unset)
            {
                // If this shortopt has an 'unset' version with '+'
                length += 3;
            }
        }
        if (options[i].longopt_name != NULL)
        {
            length += 2 + strlen(options[i].longopt_name);
            // If there is a longopt
        }
        if (options[i].param_optional && options[i].param_name != NULL)
        {
            length += 2;
            // If this option has an optional argument, print it inside brackets
        }
        if (options[i].param_name != NULL)
        {
            length += strlen(options[i].param_name);
            // If this option can be given arguments
        }
        length += 8;
        if (length > max_length)
        {
            max_length = length;
        }
    }
    return max_length;
}

void dash_print_usage(const char* argv0, const char* header, const char* footer, const char* required_arguments[], const dash_Longopt* options, FILE* output_file)
{
    size_t max_length;

    if(output_file == NULL)
    {
        output_file = stderr;
    }

    // Print header
    fputs(header, output_file);
    fputc('\n', output_file);
    fprintf(output_file, "Usage: %s [options]", argv0);
    if (required_arguments != NULL)
    {
        for (int i = 0; required_arguments[i] != NULL; i++)
        {
            fputc(' ', output_file);
            fputs(required_arguments[i], output_file);
        }
    }
    fputc('\n', output_file);

    // Calculate spacing
    max_length = calculate_print_spacing(options);

    // Start printing
    for (int i = 0; options[i].opt_name != '\0' || options[i].longopt_name != NULL; i++)
    {
        bool has_short = false;
        bool has_comma = false;
        bool has_long = false;
        bool has_param = false;
        bool param_is_opt = false;
        bool has_unsetopt = false;
        size_t length = 0;
        size_t diff;

        fputs("  ", output_file);

        if (options[i].opt_name != '\0' && options[i].longopt_name != NULL)
        {
            has_comma = true;
            length += 2;
        }
        if (options[i].opt_name != '\0')
        {
            has_short = true;
            length += 2;
            if (options[i].allow_flag_unset)
            {
                has_unsetopt = true;
                length += 3;
            }
        }
        if (options[i].longopt_name != NULL)
        {
            has_long = true;
            length += 2 + strlen(options[i].longopt_name);
        }
        if (options[i].param_optional && options[i].param_name != NULL)
        {
            param_is_opt = true;
            length += 2;
        }
        if (options[i].param_name != NULL)
        {
            has_param = true;
            length += strlen(options[i].param_name);
        }
        length += 4;
        if (has_short)
        {
            fprintf(output_file, "-%c", options[i].opt_name);
            if (has_unsetopt)
            {
                fprintf(output_file, "/+%c", options[i].opt_name);
            }
        }
        if (has_comma)
        {
            fputs(", ", output_file);
        }
        if (has_long)
        {
            fprintf(output_file, "--%s", options[i].longopt_name);
        }
        fputs(" ", output_file);
        if (param_is_opt)
        {
            fputc('[', output_file);
        }
        if (has_param)
        {
            print_in_color(output_file, options[i].param_name, COLOR_BLUE);
        }
        if (param_is_opt)
        {
            fputc(']', output_file);
        }
        fputs("  ", output_file);
        diff = max_length - length;
        for (size_t j = 0; j < diff; j++)
        {
            fputc(' ', output_file);
        }
        if(options[i].description != NULL)
        {
            for (int j = 0; options[i].description[j] != '\0'; j++)
            {
                if (options[i].description[j] != '$')
                {
                    fputc(options[i].description[j], output_file);
                }
                else
                {
                    print_in_color(output_file, options[i].param_name, COLOR_BLUE);
                }
            }
        }
        fputc('\n', output_file);
    }
    fputs(footer, output_file);
    fputc('\n', output_file);
}


void dash_print_summary(int argc, char** argv, const dash_Longopt* options, FILE* output_file)
{
    char* value;

    int structure_length = 0;

    while (options[structure_length].opt_name != '\0' || options[structure_length].longopt_name != NULL)
    {
        structure_length++;
    }
    for (int i = 0; i < structure_length; i++)
    {
        if (options[i].param_name == NULL)
        {
            if (options[i].longopt_name)
            {
                fprintf(output_file, "%-35s = (bool) ", options[i].longopt_name);
            }
            else
            {
                fprintf(output_file, "%-35c = (bool) ", options[i].opt_name);
            }
            if ((* (bool*) options[i].user_pointer))
            {
                print_in_color(output_file, "True", COLOR_GREEN);
            }
            else
            {
                print_in_color(output_file, "False", COLOR_RED);
            }
            fputc('\n', output_file);
        }
        else
        {
            if (options[i].longopt_name)
            {
                fprintf(output_file, "%-35s = (string) ", options[i].longopt_name);
            }
            else
            {
                fprintf(output_file, "%-35c = (string) ", options[i].opt_name);
            }
            if ((value = * (char**) options[i].user_pointer))
            {
                print_in_color(output_file, value, COLOR_BLUE);
            }
            else
            {
                fputs("(null)", output_file);
            }
            fputc('\n', output_file);
        }
    }
    fputs("Remaining arguments: ", output_file);
    for (int i = 0; i < argc; i++)
    {
        fprintf(output_file, "%s ", argv[i]);
    }
    fputc('\n', output_file);
}

static int strcmp_until_delimiter(const char* str1, const char* str2, char delimiter, int* index_of_delimiter)
{
    *index_of_delimiter = 0;
    while (*str1 != '\0')
    {
        if (*str1 == delimiter && *str2 == '\0')
        {
            return 0;
        }
        if (*str2 == '\0')
        {
            return -1;
        }
        if (*str1 != *str2)
        {
            return *str1 - *str2;
        }
        str1++;
        str2++;
        (*index_of_delimiter)++;
    }
    if (*str2 != '\0' && *str2 != delimiter)
    {
        return 1;
    }
    return 0;
}

static int assign_longopt(char** argument, const dash_Longopt* options, int structure_length, bool* arg_provided_with_equal)
{
    int index_of_delimiter;
    unsigned long argument_length;


    char* dest_addr;

    // Search through all allowed arguments
    for (int i = 0; i < structure_length; i++)
    {
        *arg_provided_with_equal = false;
        if (options[i].longopt_name == NULL)
        {
            continue;
        }

        // Check if argument is longopt with ' ' delimiter
        if (!strcmp(options[i].longopt_name, &(*argument)[2]))
        {
            if (options[i].param_name == NULL)
            {
                *((bool*) options[i].user_pointer) = true;
            }
            *argument = NULL;
            return i;
        }

        // Check if argument is longopt with '=' delimiter
        if (options[i].param_name != NULL && !strcmp_until_delimiter(options[i].longopt_name, &(*argument)[2], '=', &index_of_delimiter))
        {
            if ((*argument)[index_of_delimiter + 3] == '\0')
            {
                return -1;
            }
            *arg_provided_with_equal = true;
            argument_length = strlen(&(*argument)[index_of_delimiter + 3]);
            if (*((char**) options[i].user_pointer) != NULL)
            {
                return -1;
            }
            *((char**) options[i].user_pointer) = malloc((argument_length + 1) * sizeof(char));
            if(*((char**) options[i].user_pointer) == NULL)
            {
                return -1;
            }
            dest_addr = * ((char**) options[i].user_pointer);
            strcpy(&dest_addr[options[i].allow_flag_unset], &(*argument)[index_of_delimiter + 3]);
            *argument = NULL;
            return i;
        }
    }
    return -1;
}

static int assign_shortopt(char argument, const dash_Longopt* options, int structure_length, bool unset)
{
    // Search through all allowed arguments
    for (int i = 0; i < structure_length; i++)
    {
        // Check if argument is what we want
        if (options[i].opt_name != '\0' && argument == options[i].opt_name)
        {
            if (unset && !options[i].allow_flag_unset)
            {
                return -1;
            }
            if (options[i].param_name == NULL)
            {
                *((bool*) options[i].user_pointer) = !unset;
            }
            return i;
        }
    }
    return -1;
}

bool dash_arg_parser(int* argc, char* argv[], dash_Longopt* options)
{
    int argument_non_option_index = 1;
    int argument_non_option_count = 1;

    int structure_length = 0;

    int found_structure_index = -1;
    bool last_opt_was_unset = false;
    bool long_opt_was_provided_with_equal = false;

    bool option_should_have_argument;

    unsigned long argument_length;
    unsigned long unset_argument_length;

    char* dest_addr;
    char* unset_dest_addr;
    char* short_dest_addr;

    int c;

    while (options[structure_length].opt_name != '\0' || options[structure_length].longopt_name != NULL)
    {
        // Can't dereference a NULL pointer
        if (options[structure_length].user_pointer == NULL)
        {
            return false;
        }

        // We put each pointer to NULL so we can know if they were allocated or not int the future.
        if(options[structure_length].param_name == NULL)
        {
            *((bool*)options[structure_length].user_pointer) = false;
        }
        else
        {
            *((char**)options[structure_length].user_pointer) = NULL;
        }
        structure_length++;
    }

    for (int i = 1; i < *argc; i++)
    {
        // Previous flag did not specify argument
        if (found_structure_index != -1 && !long_opt_was_provided_with_equal)
        {
            // We need an argument
            if (options[found_structure_index].param_name != NULL && !options[found_structure_index].param_optional)
            {
                if (argv[i][0] == '-')
                {
                    return false;
                }
                argument_length = strlen(argv[i]);
                if (options[found_structure_index].allow_flag_unset)
                {
                    argument_length += 1;
                }
                if (* ((char**) options[found_structure_index].user_pointer) != NULL)
                {
                    return false;
                }
                *((char**) options[found_structure_index].user_pointer) = malloc((argument_length + 1) * sizeof(char));
                if(*((char**) options[found_structure_index].user_pointer) == NULL)
                {
                    return false;
                }
                dest_addr = * ((char**) options[found_structure_index].user_pointer);
                strcpy(&dest_addr[options[found_structure_index].allow_flag_unset], argv[i]);
                if (options[found_structure_index].allow_flag_unset)
                {
                    dest_addr[0] = last_opt_was_unset ? '+' : '-';
                }
                argv[i] = NULL;
                found_structure_index = -1;
                continue;
            }
            // Try to search for an argument
            else if (options[found_structure_index].param_name != NULL)
            {
                if (argv[i][0] != '-')
                {
                    argument_length = strlen(argv[i]);
                    if (options[found_structure_index].allow_flag_unset)
                    {
                        argument_length += 1;
                    }
                    if (* ((char**) options[found_structure_index].user_pointer) != NULL)
                    {
                        return false;
                    }
                    *((char**) options[found_structure_index].user_pointer) = malloc((argument_length + 1) * sizeof(char));
                    if(*((char**) options[found_structure_index].user_pointer) == NULL)
                    {
                        return false;
                    }
                    dest_addr = * ((char**) options[found_structure_index].user_pointer);
                    strcpy(&dest_addr[options[found_structure_index].allow_flag_unset], argv[i]);
                    if (options[found_structure_index].allow_flag_unset)
                    {
                        dest_addr[0] = last_opt_was_unset ? '+' : '-';
                    }
                    argv[i] = NULL;
                    found_structure_index = -1;
                    continue;
                }
                else
                {
                    *((char**) options[found_structure_index].user_pointer) = malloc((1 + options[found_structure_index].allow_flag_unset) * sizeof(char));
                    if(*((char**) options[found_structure_index].user_pointer) == NULL)
                    {
                        return false;
                    }
                    (* ((char**) options[found_structure_index].user_pointer))[options[found_structure_index].allow_flag_unset] = '\0';
                    if (options[found_structure_index].allow_flag_unset)
                    {
                        (* ((char**) options[found_structure_index].user_pointer))[0] = last_opt_was_unset ? '+' : '-';
                    }
                }
            }
        }

        long_opt_was_provided_with_equal = false;
        found_structure_index = -1;

        // Check if argument begins with a dash or a plus
        if (argv[i][0] != '-' && argv[i][0] != '+')
        {
            argument_non_option_count += 1;
            continue;
        }

        // If argument begins with a plus, unset shortopt
        if (argv[i][0] == '+')
        {
            last_opt_was_unset = true;
            c = 1;
            option_should_have_argument = false;
            while (argv[i][c] != '\0')
            {
                if (option_should_have_argument == true)
                {
                    argument_length = strlen(&argv[i][c]);
                    if (options[found_structure_index].allow_flag_unset)
                    {
                        argument_length += 1;
                    }
                    if (* ((char**) options[found_structure_index].user_pointer) != NULL)
                    {
                        return false;
                    }
                    * ((char**) options[found_structure_index].user_pointer) = malloc((argument_length + 1) * sizeof(char));
                    if(*((char**) options[found_structure_index].user_pointer) == NULL)
                    {
                        return false;
                    }
                    unset_dest_addr = * ((char**) options[found_structure_index].user_pointer);
                    strcpy(&unset_dest_addr[options[found_structure_index].allow_flag_unset], &argv[i][c]);
                    if (options[found_structure_index].allow_flag_unset)
                    {
                        unset_dest_addr[0] = '+';
                    }
                    found_structure_index = -1;
                    break;
                }
                if ((found_structure_index = assign_shortopt(argv[i][c], options, structure_length, true)) == -1)
                {
                    return false;
                }
                option_should_have_argument = (options[found_structure_index].param_name != NULL && options[found_structure_index].param_optional);
                c++;
            }
            argv[i] = NULL;
            continue;
        }

        last_opt_was_unset = false;

        // Double dash, long opt
        if (argv[i][1] == '-')
        {
            // Only double dash, end of parsing arguments
            if (argv[i][2] == '\0')
            {
                argument_non_option_count += *argc - i - 1;
                argv[i] = NULL;
                goto REORGANIZE;
            }
            if ((found_structure_index = assign_longopt(&argv[i], options, structure_length, &long_opt_was_provided_with_equal)) == -1)
            {
                return false;
            }
        }
        // Single dash, ignore (will be used as stdin)
        else if (argv[i][1] == '\0')
        {
            argument_non_option_count += 1;
            continue;
        }
        // Short opt
        else
        {
            c = 1;
            option_should_have_argument = false;
            while (argv[i][c] != '\0')
            {
                if (option_should_have_argument == true)
                {
                    unset_argument_length = strlen(&argv[i][c]);
                    if (options[found_structure_index].allow_flag_unset)
                    {
                        unset_argument_length += 1;
                    }
                    if (* ((char**) options[found_structure_index].user_pointer) != NULL)
                    {
                        return false;
                    }
                    * ((char**) options[found_structure_index].user_pointer) = malloc((unset_argument_length + 1) * sizeof(char));
                    short_dest_addr = * ((char**) options[found_structure_index].user_pointer);
                    strcpy(&short_dest_addr[options[found_structure_index].allow_flag_unset], &argv[i][c]);
                    if (options[found_structure_index].allow_flag_unset)
                    {
                        short_dest_addr[0] = '-';
                    }
                    found_structure_index = -1;
                    break;
                }
                if ((found_structure_index = assign_shortopt(argv[i][c], options, structure_length, false)) == -1)
                {
                    return false;
                }
                option_should_have_argument = (options[found_structure_index].param_name != NULL && !options[found_structure_index].param_optional);
                c++;
            }
            argv[i] = NULL;
        }
    }

REORGANIZE:

    if (found_structure_index != -1 && options[found_structure_index].param_optional && options[found_structure_index].param_name != NULL && !long_opt_was_provided_with_equal)
    {
        if (* ((char**) options[found_structure_index].user_pointer) != NULL)
        {
            return false;
        }
        *((char**) options[found_structure_index].user_pointer) = malloc((1 + options[found_structure_index].allow_flag_unset) * sizeof(char));
        if(*((char**) options[found_structure_index].user_pointer) == NULL)
        {
            return false;
        }
        (* ((char**) options[found_structure_index].user_pointer))[options[found_structure_index].allow_flag_unset] = '\0';
        if (options[found_structure_index].allow_flag_unset)
        {
            (* ((char**) options[found_structure_index].user_pointer))[0] = last_opt_was_unset ? '+' : '-';
        }
    }

    if (found_structure_index != -1 && options[found_structure_index].param_name != NULL && !options[found_structure_index].param_optional && !long_opt_was_provided_with_equal)
    {
        return false;
    }

    for (int i = 1; i < *argc; i++)
    {
        if (argv[i] != NULL)
        {
            argv[argument_non_option_index] = argv[i];
            if (i != argument_non_option_index++)
            {
                argv[i] = NULL;
            }
        }
    }

    *argc = argument_non_option_count;

    return true;
}

void dash_free(dash_Longopt* options)
{
    int structure_length = 0;
    while (options[structure_length].opt_name != '\0' || options[structure_length].longopt_name != NULL)
    {
        // Can't dereference a NULL pointer
        if (options[structure_length].user_pointer == NULL)
        {
            continue;
        }

        // We put each pointer to NULL so we can know if they were allocated or not int the future.
        if(options[structure_length].param_name != NULL)
        {
            char** p = (char**)options[structure_length].user_pointer;
            free(*p);
            *p = NULL;
        }
        structure_length++;
    }
}