import powermake
import powermake.compilers
import powermake.linkers


def on_build(config: powermake.Config):
    files = powermake.filter_files(powermake.get_files("**/*.c"), "**/main.c")

    config.c_compiler = powermake.compilers.CompilerClang()
    config.linker = powermake.linkers.LinkerClang()

    config.add_c_flags("-ffuzzer")
    config.add_ld_flags("-ffuzzer")
    config.add_shared_libs("pcap")
    config.add_includedirs("./")

    objects = powermake.compile_files(config, files)

    powermake.link_files(config, objects)


powermake.run("fuzzer", build_callback=on_build)
