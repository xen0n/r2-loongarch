#!/usr/bin/env python3

'''
input: lines like

000000 1010 IMM_________ RJ___ RD___   addiw       **4 -- li is sugar for `addiw rd, zero, imm`

output: lines like

{ "sext.h",     RR,     0x00005800, 0xfffffc00, 0 },

various things are guessed or given sensible defaults, manual adjusts are needed after conversion
'''

import re
import sys
import typing

SPACES = re.compile(r'\s+')

class Matcher:
    def __init__(self, mnemonics: str, fmt: str, match: int, mask: int) -> None:
        self.mnemonics = mnemonics
        self.fmt = fmt
        self.match = match
        self.mask = mask
        # TODO: render_flag

    def to_c(self) -> str:
        mnemonics_f = f'"{self.mnemonics}", '
        fmt_f = f'{self.fmt}, '
        return f'    {{ {mnemonics_f:14}{fmt_f:8}0x{self.match:08x}, 0x{self.mask:08x}, 0 }},'


def join_bits_to_int(bits: typing.List[int]) -> int:
    return sum((2 ** power) * bit for (power, bit) in enumerate(reversed(bits)))


def process_line(l: str) -> Matcher:
    # coalesce spaces
    l = SPACES.sub(' ', l)
    # split into fragments
    frags = l.split(' ')

    match_bits = []
    mask_bits = []
    bits_collected = 0
    mnemonics = ''
    num_seen_regs = 0
    num_seen_imms = 0
    num_seen_imm_bits = 0
    partial_imm_flag = False
    for frag in frags:
        if bits_collected > 32:
            raise ValueError('malformed line: insn bits more than 32 already')

        if bits_collected == 32:
            # this fragment must be insn name, record then break
            # all insn names are without spaces
            mnemonics = frag
            break

        # this is a fragment describing part of the insn
        # turn into mask
        for ch in frag:
            if ch == '0':
                match_bits.append(0)
                mask_bits.append(1)
            elif ch == '1':
                match_bits.append(1)
                mask_bits.append(1)
            else:
                match_bits.append(0)
                mask_bits.append(0)

        bits_collected += len(frag)

        # inspect into frag to guess insn format
        if frag[0] in {'R', 'F'}:
            num_seen_regs += 1
        elif 'IMM' in frag:
            if not partial_imm_flag:
                num_seen_imms += 1
                if 'LO' in frag or 'HI' in frag:
                    partial_imm_flag = True
            num_seen_imm_bits += len(frag)

    match = join_bits_to_int(match_bits)
    mask = join_bits_to_int(mask_bits)
    fmt = guess_insn_fmt(num_seen_regs, num_seen_imms, num_seen_imm_bits)

    return Matcher(mnemonics, fmt, match, mask)


def guess_insn_fmt(num_regs: int, num_imms: int, total_imm_bits: int) -> str:
    if num_imms == 0:
        if num_regs == 2:
            return 'RR'
        elif num_regs == 3:
            return 'RRR'
        elif num_regs == 4:
            return 'FFFF'
    elif num_imms == 2:
        # this is the only format with 2 immediates
        return 'RRI6I6'
    elif num_imms == 1:
        if 5 <= total_imm_bits <= 6 and num_regs == 2:
            return 'RRI6'
        elif total_imm_bits == 8 and num_regs == 2:
            return 'RRI8'
        elif 10 <= total_imm_bits <= 12 and num_regs == 2:
            return 'RRI12'
        elif total_imm_bits == 14 and num_regs == 2:
            return 'RRI14'
        elif total_imm_bits == 16 and num_regs == 2:
            return 'RRI16'
        elif total_imm_bits == 20 and num_regs == 1:
            return 'AUI20'
        elif total_imm_bits == 21 and num_regs == 1:
            return 'RI21'
        elif total_imm_bits == 25 and num_regs == 0:
            return 'I25'

    return 'UNK'


def main() -> None:
    for line in sys.stdin:
        # remove final \n
        line = line.strip()
        print(process_line(line).to_c())


if __name__ == '__main__':
    main()
