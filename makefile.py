import os
import powermake


def on_build(config: powermake.Config):
    files = powermake.filter_files(powermake.get_files("**/*.c"), "**/fuzzer.c")

    if not config.debug:
        config.add_flags("-flto")

    config.add_flags("-fsecurity")
    config.add_shared_libs("pcap")
    config.add_includedirs("./")

    objects = powermake.compile_files(config, files)

    powermake.link_files(config, objects)


powermake.run("network_analyzer", build_callback=on_build)
