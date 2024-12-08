import powermake


def on_build(config: powermake.Config):
    files = powermake.filter_files(powermake.get_files("**/*.c"), "**/fuzzer.c")

    config.add_c_flags("-fsecurity")
    config.add_ld_flags("-fsecurity")
    config.add_shared_libs("pcap")
    config.add_includedirs("./")

    objects = powermake.compile_files(config, files)

    powermake.link_files(config, objects)


powermake.run("my_wireshark", build_callback=on_build)
