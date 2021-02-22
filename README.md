# Radare2/Rizin plugins for LoongArch

This is work in progress.

The assembler syntax is made up by me to resemble MIPS and RISC-V assembly.
Instruction mnemonics are mainly borrowed from RISC-V and MIPS, though I have
invented names for some novel instructions not found elsewhere.

Some mnemonics are prefixed with `!`, that means the semantic is not entirely
clear for these instructions.

Recently radare2 got forked into rizin, however due to the young age of fork,
the APIs are nearly identical apart from some renamings. This project currently
supports only radare2 because that is what Gentoo currently packages.

## Features

* [x] Asm plugin
* [ ] Analysis plugin

## Install

```sh
# compile
make

# install into your user plugin directory
# the directory will be created if it doesn't exist yet
make install
```

## License

GPLv3 or later, see [LICENSE].
