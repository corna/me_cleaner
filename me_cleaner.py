#!/usr/bin/python

# Copyright (C) 2016 Nicola Corna <nicola@corna.info>
#
# me_cleaner is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# me_cleaner is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with me_cleaner.  If not, see <http://www.gnu.org/licenses/>.
#

import sys
import itertools
from struct import pack, unpack


unremovable_huff_modules = ("BUP", "ROMP")


def get_chunks_offsets(llut, me_start):
    chunk_count = unpack("<I", llut[0x04:0x08])[0]
    huffman_stream_end = sum(unpack("<II", llut[0x10:0x18])) + me_start
    nonzero_offsets = [huffman_stream_end]
    offsets = []

    for i in range(0, chunk_count):
        chunk = llut[0x40 + i * 4:0x44 + i * 4]
        offset = 0

        if chunk[3] != 0x80:
            offset = unpack("<I", chunk[0:3] + b"\x00")[0] + me_start

        offsets.append([offset, 0])
        if offset != 0:
            nonzero_offsets.append(offset)

    nonzero_offsets.sort()

    for i in offsets:
        if i[0] != 0:
            i[1] = nonzero_offsets[nonzero_offsets.index(i[0]) + 1]

    return offsets


def fill_range(f, start, end, fill):
    block = fill * 4096
    f.seek(start, 0)
    f.writelines(itertools.repeat(block, (end - start) // 4096))
    f.write(block[:(end - start) % 4096])


def remove_huffman_modules(f, mod_headers, chunks_offsets, base, chunk_size):
    unremovable_huff_chunks = []

    for mod_header in mod_headers:
        flags = unpack("<I", mod_header[0x50:0x54])[0]
        comp_type = (flags >> 4) & 7

        if comp_type == 0x01:
            name = mod_header[0x04:0x14].rstrip(b"\x00").decode("ascii")

            if name in unremovable_huff_modules:
                module_base = unpack("<I", mod_header[0x34:0x38])[0]
                module_size = unpack("<I", mod_header[0x3c:0x40])[0]
                first_chunk_num = (module_base - base) // chunk_size
                last_chunk_num = first_chunk_num + module_size // chunk_size

                unremovable_huff_chunks += \
                    [x for x in chunks_offsets[first_chunk_num:
                     last_chunk_num + 1] if x[0] != 0]

    removable_huff_chunks = []

    for chunk in chunks_offsets:
        if all(not(unremovable_chunk[0] <= chunk[0] < unremovable_chunk[1] or
                   unremovable_chunk[0] < chunk[1] <= unremovable_chunk[1])
               for unremovable_chunk in unremovable_huff_chunks):
            removable_huff_chunks.append(chunk)

    for removable_chunk in removable_huff_chunks:
        if removable_chunk[1] > removable_chunk[0]:
            fill_range(f, removable_chunk[0], removable_chunk[1], b"\xff")


def module_removal_report(f, mod_headers, ftpr_offset, lzma_start, lzma_end,
                          lzma_removed, huffman_removed):
    for mod_header in mod_headers:
        name = mod_header[0x04:0x14].rstrip(b"\x00").decode("ascii")
        flags = unpack("<I", mod_header[0x50:0x54])[0]
        comp_type = (flags >> 4) & 7

        sys.stdout.write(" {:<16} ".format(name))

        if comp_type == 0x00 or comp_type == 0x02:
            start = unpack("<I", mod_header[0x38:0x3C])[0] + ftpr_offset
            size = unpack("<I", mod_header[0x40:0x44])[0]
            sys.stdout.write("(LZMA, 0x{:06x} - 0x{:06x}): "
                             .format(start, start + size))

            if start >= lzma_start and start + size <= lzma_end:
                if lzma_removed:
                    print("removed")
                else:
                    print("NOT removed")
            else:
                print("outside the LZMA region ({:#x} - {:#x}), skipping"
                      .format(lzma_start, lzma_end))

        elif comp_type == 0x01:
            sys.stdout.write("(Huffman, fragmented data ): ")

            if name in unremovable_huff_modules:
                print("NOT removed, essential")
            else:
                if huffman_removed:
                    print("removed")
                else:
                    print("NOT removed")

        else:
            print("unknown compression, skipping")


if len(sys.argv) != 2 or sys.argv[1] == "-h" or sys.argv[1] == "--help":
    print("Usage: \n"
          " me_cleaner.py me_image.bin\n"
          "or\n"
          " me_cleaner.py full_dump.bin")
else:
    with open(sys.argv[1], "r+b") as f:
        f.seek(0x10, 0)
        magic = f.read(4)

        if magic == b"$FPT":
            print("ME image detected")
            me_start = 0
            f.seek(0, 2)
            me_end = f.tell()

        elif magic == b"\x5a\xa5\xf0\x0f":
            print("Full image detected")
            f.seek(0x14, 0)
            flmap0 = unpack("<I", f.read(4))[0]
            nr = flmap0 >> 24 & 0x7
            frba = flmap0 >> 12 & 0xff0
            if nr >= 2:
                f.seek(frba + 0x8, 0)
                flreg2 = unpack("<I", f.read(4))[0]
                me_start = (flreg2 & 0x1fff) << 12
                me_end = flreg2 >> 4 & 0x1fff000 | 0xfff

                if me_start >= me_end:
                    sys.exit("The ME region in this image has been disabled")

                f.seek(me_start + 0x10)
                if f.read(4) != b"$FPT":
                    sys.exit("The ME region is corrupted or missing")

                print("The ME region goes from {:#x} to {:#x}"
                      .format(me_start, me_end))
            else:
                sys.exit("This image does not contains a ME firmware (NR = {})"
                         .format(nr))
        else:
            sys.exit("Unknown image")

        print("Found FPT header at {:#x}".format(me_start + 0x10))

        f.seek(me_start + 0x14)
        entries = unpack("<I", f.read(4))[0]
        print("Found {} partition(s)".format(entries))

        f.seek(me_start + 0x14, 0)
        header_len = unpack("B", f.read(1))[0]

        f.seek(me_start + 0x30, 0)
        partitions = f.read(entries * 0x20)

        ftpr_header = b""

        for i in range(entries):
            if partitions[i * 0x20:(i * 0x20) + 4] == b"FTPR":
                ftpr_header = partitions[i * 0x20:(i + 1) * 0x20]
                break

        if ftpr_header == b"":
            sys.exit("FTPR header not found, this image doesn't seem to be "
                     "valid")

        ftpr_offset, ftpr_lenght = unpack("<II", ftpr_header[0x08:0x10])
        ftpr_offset += me_start
        print("Found FTPR header: FTPR partition spans from {:#x} to {:#x}"
              .format(ftpr_offset, ftpr_offset + ftpr_lenght))
        print("Removing extra partitions...")

        fill_range(f, me_start + 0x30, ftpr_offset, b"\xff")
        fill_range(f, ftpr_offset + ftpr_lenght, me_end, b"\xff")

        print("Removing extra partition entries in FPT...")
        f.seek(me_start + 0x30, 0)
        f.write(ftpr_header)
        f.seek(me_start + 0x14, 0)
        f.write(pack("<I", 1))

        print("Removing EFFS presence flag...")
        f.seek(me_start + 0x24, 0)
        flags = unpack("<I", f.read(4))[0]
        flags &= ~(0x00000001)
        f.seek(me_start + 0x24, 0)
        f.write(pack("<I", flags))

        f.seek(me_start, 0)
        header = bytearray(f.read(0x30))
        checksum = (0x100 - (sum(header) - header[0x1b]) & 0xff) & 0xff

        print("Correcting checksum (0x{:02x})...".format(checksum))
        # The checksum is just the two's complement of the sum of the first
        # 0x30 bytes (except for 0x1b, the checksum itself). In other words,
        # the sum of the first 0x30 bytes must be always 0x00.
        f.seek(me_start + 0x1b, 0)
        f.write(pack("B", checksum))

        f.seek(ftpr_offset, 0)
        if f.read(4) == b"$CPD":
            me11 = True
            num_entries = unpack("<I", f.read(4))[0]
            f.seek(ftpr_offset + 0x10 + num_entries * 0x18 + 0x24)
        else:
            me11 = False
            f.seek(ftpr_offset + 0x24, 0)

        version = unpack("<HHHH", f.read(0x08))
        print("ME firmware version {}"
              .format('.'.join(str(i) for i in version)))

        if not me11:
            print("Reading FTPR modules list...")
            f.seek(ftpr_offset + 0x1c, 0)
            tag = f.read(4)

            if tag == b"$MN2":
                f.seek(ftpr_offset + 0x20, 0)
                num_modules = unpack("<I", f.read(4))[0]
                f.seek(ftpr_offset + 0x290, 0)
                mod_headers = [f.read(0x60) for i in range(0, num_modules)]

                if any(mod_h.startswith(b"$MME") for mod_h in mod_headers):

                    lzma_removed = False
                    huffman_removed = False

                    f.seek(ftpr_offset + 0x18, 0)
                    size = unpack("<I", f.read(4))[0]
                    llut_start = ftpr_offset + (size * 4 + 0x3f) & ~0x3f

                    f.seek(llut_start + 0x10, 0)
                    huff_start, huff_size = unpack("<II", f.read(8))
                    huff_start += me_start
                    lzma_start = huff_start + huff_size

                    print("Wiping LZMA section ({:#x} - {:#x})..."
                          .format(lzma_start, ftpr_offset + ftpr_lenght))
                    fill_range(f, lzma_start, ftpr_offset + ftpr_lenght,
                               b"\xff")
                    lzma_removed = True

                    f.seek(llut_start, 0)
                    llut = f.read(4)
                    if llut == b"LLUT":
                        llut += f.read(0x3c)

                        chunk_count = unpack("<I", llut[0x4:0x8])[0]
                        base = unpack("<I", llut[0x8:0xc])[0] + 0x10000000
                        huff_data_len = unpack("<I", llut[0x10:0x14])[0]
                        chunk_size = unpack("<I", llut[0x30:0x34])[0]

                        llut += f.read(chunk_count * 4 + huff_data_len)
                        chunks_offsets = get_chunks_offsets(llut, me_start)

                        print("Wiping removable Huffman modules...")
                        remove_huffman_modules(f, mod_headers, chunks_offsets,
                                               base, chunk_size)
                        huffman_removed = True
                    else:
                        print("Can't find the LLUT region in the FTPR "
                              "partition")

                    module_removal_report(f, mod_headers, ftpr_offset,
                                          lzma_start,
                                          ftpr_offset + ftpr_lenght,
                                          lzma_removed, huffman_removed)
                else:
                    print("Can't find the $MN2 modules in the FTPR partition")
            else:
                print("Wrong FTPR partition tag ({})".format(tag))
        else:
            print("Modules removal in ME v11 or greater is not yet supported")

        print("Done! Good luck!")

