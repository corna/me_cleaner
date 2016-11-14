#!/usr/bin/python3

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
from struct import *


def fill_range(f, start, end, fill):
    block = fill * 4096
    f.seek(start, 0)
    f.writelines(itertools.repeat(block, (end - start) // 4096))
    f.write(fill[:(end - start) % 4096])

if len(sys.argv) != 2 or sys.argv[1] == "-h" or sys.argv[1] == "--help":
    print("Usage: me_cleaner.py me_image.bin")
else:
    with open(sys.argv[1], "r+b") as f:
        f.seek(0x10, 0)
        fpt_header = f.read(4)

        if fpt_header == b"$FPT":
            print("Found FPT header at 0x10")

            entries = unpack("<I", f.read(4))[0]
            print("Found {} partition(s)".format(entries))

            f.seek(0x02, 1)
            header_len = unpack("<B", f.read(1))[0]
            f.seek(0x30, 0)
            partitions = f.read(entries * 0x20)

            ftpr_header = b""
            ftpr_offset = 0
            ftpr_lenght = 0

            for i in range(entries):
                if partitions[i * 0x20:(i * 0x20) + 4] == b"FTPR":
                    ftpr_header = partitions[i * 0x20:(i + 1) * 0x20]
                    break

            if ftpr_header != b"":
                ftpr_offset = unpack("<I", ftpr_header[0x08:0x0C])[0]
                ftpr_lenght = unpack("<I", ftpr_header[0x0C:0x10])[0]
                print("Found FTPR header: FTPR partition spans from "
                      "0x{:02x} to 0x{:02x}".format(ftpr_offset,
                                                    ftpr_offset + ftpr_lenght))
                print("Removing extra partitions...")

                fill_range(f, 0x30, ftpr_offset, b"\xFF")
                f.seek(0, 2)
                fill_range(f, ftpr_offset + ftpr_lenght, f.tell(), b"\xFF")

                print("Removing extra partition entries in FPT...")
                f.seek(0x30, 0)
                f.write(ftpr_header)
                f.seek(0x14, 0)
                f.write(pack("<I", 1))
                f.seek(0x00, 0)
                checksum_bytes = f.read(0x30)
                f.seek(0x1b, 0)

                print("Correcting checksum...")
                # The checksum is just the two's complement of the sum of the
                # first 0x30 bytes (except for 0x1b, the checksum itself). In
                # other words, the sum of the first 0x30 bytes must be always
                # 0x00.
                f.write(pack("B", (0x100 -
                             (sum(checksum_bytes) - checksum_bytes[0x1b]) &
                             0xff) & 0xff))

                print("All done! Good luck!")

            else:
                print("FTPR header not found, this image doesn't seem to be "
                      "valid")

        else:
            print("{} is not a valid Intel ME image (FPT not found)"
                  .format(sys.argv[1]))

