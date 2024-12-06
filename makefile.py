import powermake


def on_build(config: powermake.Config):
    files = powermake.get_files("**/*.c")

    config.add_c_flags("-Wsecurity")
    config.add_shared_libs("pcap")

    objects = powermake.compile_files(config, files)

    powermake.link_files(config, objects)


powermake.run("my_wireshark", build_callback=on_build)
