# Network Analyzer

The aim of this project is to create a tool capable of analyzing network frames under Linux and displaying them in a human-readable way.

- [Network Analyzer](#network-analyzer)
  - [Project architecture](#project-architecture)
  - [Compilation](#compilation)
    - [What is PowerMake and why did you use it on this project?](#what-is-powermake-and-why-did-you-use-it-on-this-project)
    - [Using PowerMake](#using-powermake)
    - [Compiler warnings](#compiler-warnings)
  - [Using the program](#using-the-program)
    - [Display and screen size](#display-and-screen-size)
    - [Supported protocols](#supported-protocols)
  - [Security](#security)
    - [Conclusion](#conclusion)


## Project architecture

At the root of the project are 2 folders:
- lib
- src

`lib` contains:
- the OpenSource [Dash] library (https://github.com/nothixy/dash), originally designed by Valentin Foulon, then fine-tuned and made more reliable by me. This library has simply been copied here for simplicity's sake.

- The `common.h` and `common.c` files, which contain some display functions that I use in several places in the project.

`src` contains the core code of the program.
- `main.c` reads the command line before handing over to the `run_pcap` function in `listener.c`.

- `listener.c` contains all the code linked to the pcap library. This file implements the `run_pcap` function, which opens the interfaces (online or offline) and starts the capture.

- each network frame is analyzed in `decapsulation.c`, which calls the appropriate functions to read the protocols of the physical layer, the network layer, the transport layer and the application layer.

- The `*_layer` folders contain the files for displaying the various protocols.

- You may notice the presence of a `fuzzer.c` file, which is not compiled with the project. Its role is discussed in the [security](#security) section.


## Compilation


This project is designed to be compiled with [PowerMake](https://github.com/mactul/powermake).


### What is PowerMake and why did you use it on this project?


PowerMake is a tool for automating compilation, just like GNU Make, but with a host of very pleasant features that make development much easier.

PowerMake is a tool I've developed myself over the last 6 months which provides me with an enormous amount of comfort, which I'm now finding hard to get rid of.

The features I'm using particularly in this project include

- compilation of all .c files corresponding to a well-defined pattern.

- the ability to compile in release or debug in different folders with different compilation options by adding a simple argument on the command line

- translation of compiler flags, so I can simply add the `-fsecurity` flag, which activates all the security-enhancing flags compatible with my compiler (on my machine, that's around thirty flags).



### Using PowerMake


PowerMake is easily installed via pip (assuming python >= 3.7 and pip are already installed).
```sh
pip3 install -U powermake
```


Once PowerMake is installed, simply run `makefile.py` with `python`:
```sh
python3 makefile.py
```

> [!NOTE]
> The generated program will be located at `./build/Linux/x64/release/bin/network_analyzer`.


I can use the `-r` option to force recompiling, the `-v` option to see the commands run and the `-d` option to compile my program in debug mode:

```sh
python3 makefile.py -rvd
```

> [!NOTE]
> The generated program will be located at `./build/Linux/x64/debug/bin/network_analyzer`.


Other options are available, the complete list can be found using:

```sh
python3 makefile.py -h
```


### Compiler warnings

I compile my code under GCC 14.2 with a huge number of warnings and options, some of which are brand new and still experimental.

If you're using an older compiler, PowerMake should automatically remove incompatible options, but you may get warnings that I don't have.

In particular, you're likely to get a `-Wcpp` warning which triggers if your system doesn't support `-D_FORTIFY_SOURCE=3` and drops the option to value 2.

You may also get a false-positive from the `-fanalyzer` option, as in older versions this option regularly raised non-existent errors.

## Using the program

The compiled program can be found in `./build/Linux/x64/release/bin/network_analyzer` or `./build/Linux/x64/debug/bin/network_analyzer`.


To listen on a network interface, this program requires root rights.  
You can launch the program as follows:

```sh
sudo ./build/Linux/x64/release/bin/network_analyzer
```

If you run it like this, with no arguments, the program will ask you to select an interface from a list, then start displaying packets passing over that interface.

You can also provide an interface for it to start immediately.

```sh
sudo ./build/Linux/x64/release/bin/network_analyzer -i wlan0
```

The other operating mode is the offline mode, which reads a .cap, .pcap or .pcapng file and displays the packets captured in it. This mode does not require root permissions.
```sh
./build/Linux/x64/release/bin/network_analyzer -o file.pcap
```


You can also add a filter with the `-f` option, or choose a verbosity level between 1 and 3 with the `-v` option.  
Finally, the `-h` option displays help.


### Display and screen size

In verbose mode, the program displays data as a kind of hexdump, with data in hexadecimal and ascii next to it.  
To make this display easier to read, the number of columns displayed is always a multiple of 2, but this display also adapts to the size of the terminal, so it's the largest multiple of 2 that can be displayed in the given console space.


### Supported protocols

The program supports the following protocols:

- Ethernet
- IPv4
- IPv6
- IPv6 encapsulated in IPv4
- ARP
- ICMP
- ICMPv6
- UDP
- TCP
- SCTP
- DHCP
- DNS
- HTTP(S)
- SMTP(S)
- POP
- IMAP(S)
- Telnet
- FTP(S)

As all these protocols have many special cases, it's not possible to have a concise dataset that covers all the cases I've been able to set up. The smallest dataset I've been able to generate that covers most of my code is 903 files long, which isn't reasonable to include as a demo dataset.

I therefore include a restricted dataset (demo_files) containing files that are sometimes difficult to find, allowing you to see a reasonable portion of the work provided.

## Security

Any program connected to the network is at risk when it comes to security. This is all the more true for a program such as this one, which analyzes dozens of protocols and quickly runs the risk of buffer overflow if a poorly formatted packet is detected.


Throughout the writing of this program, I tried to keep this aspect in mind and produce the most reliable program possible. Here are some of the measures I implemented:

- Compilation with as many security mitigation options as possible (ASLR, Full Relro, Stack Canaries, etc.).

- The code never trusts any size value indicated by packets, and always checks that what is indicated is within the buffer bounds.

- The code has been extensively tested using fuzzers (see explanation below).


A fuzzer is a program which, given a given corpus of valid files (in this case pcap files), will slightly mutate each file in the corpus and then run my program with the mutated file. If the mutated file allows a new branch of the code to be explored, it is added to the corpus. This process is repeated in a loop, for hours on end, so that every line of source code is tested with all sorts of extravagant values and if there's at least one way to make the program crash, the fuzzer will almost certainly succeed after a while.

I've used 2 different fuzzers, *LLVM libfuzzer* and *American Fuzzy Loop*, the latter being more complex to set up, I'll only detail the use of the former.


*LLVM libfuzzer* is integrated into Clang, so it can be used with Clang's other analysis tools. In particular, I use it with the address sanitizer so that an exception is generated whenever a read/write is performed outside the buffer limits or there is a memory leak.  
To use it, simply compile the program by replacing `main.c` with `fuzzer.c` and add the options `fsanitize=address,fuzzer`, the `fuzzer_makefile.py` file is there to do this:

```sh
python3 fuzzer_makefile.py -rv
```

Next, run the program, providing a corpus of files to be mutated.
```sh
./build/Linux/x64/release/bin/fuzzer ./pcap_files/
```

Then wait for a possible crash.


### Conclusion

After more than a hundred hours of testing my code at a rate of 2 million files per second, without generating a crash, I can now say that it is unlikely that it is possible to crash my code and that it is even more unlikely that a flaw could be exploited. So there's no particular problem in exposing it to the network.