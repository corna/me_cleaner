#!/usr/bin/python

# me_cleaner -  Tool for partial deblobbing of Intel ME/TXE firmware images
# Copyright (C) 2016, 2017 Nicola Corna <nicola@corna.info>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#

import sys
import itertools
import binascii
import hashlib
import argparse
import shutil
from struct import pack, unpack


min_ftpr_offset = 0x400
spared_blocks = 4
unremovable_modules = ("BUP", "ROMP")


class OutOfRegionException(Exception):
    pass


class regionFile:
    def __init__(self, f, region_start, region_end):
        self.f = f
        self.region_start = region_start
        self.region_end = region_end

    def read(self, n):
        return self.f.read(n)

    def readinto(self, b):
        return self.f.readinto(b)

    def seek(self, offset):
        return self.f.seek(offset)

    def write_to(self, offset, data):
        if offset >= self.region_start and \
           offset + len(data) <= self.region_end:
            self.f.seek(offset)
            return self.f.write(data)
        else:
            raise OutOfRegionException()

    def fill_range(self, start, end, fill):
        if start >= self.region_start and end <= self.region_end:
            if start < end:
                block = fill * 4096
                self.f.seek(start)
                self.f.writelines(itertools.repeat(block,
                                                   (end - start) // 4096))
                self.f.write(block[:(end - start) % 4096])
        else:
            raise OutOfRegionException()

    def move_range(self, offset_from, size, offset_to, fill):
        if offset_from >= self.region_start and \
           offset_from + size <= self.region_end and \
           offset_to >= self.region_start and \
           offset_to + size <= self.region_end:
            for i in range(0, size, 4096):
                self.f.seek(offset_from + i, 0)
                block = self.f.read(4096 if size - i >= 4096 else size - i)
                self.f.seek(offset_from + i, 0)
                self.f.write(fill * len(block))
                self.f.seek(offset_to + i, 0)
                self.f.write(block)
        else:
            raise OutOfRegionException()


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


def remove_modules(f, mod_headers, ftpr_offset, me_end):
    comp_str = ("Uncomp.", "Huffman", "LZMA")
    unremovable_huff_chunks = []
    chunks_offsets = []
    base = 0
    chunk_size = 0
    end_addr = 0

    for mod_header in mod_headers:
        name = mod_header[0x04:0x14].rstrip(b"\x00").decode("ascii")
        offset = unpack("<I", mod_header[0x38:0x3C])[0] + ftpr_offset
        size = unpack("<I", mod_header[0x40:0x44])[0]
        flags = unpack("<I", mod_header[0x50:0x54])[0]
        comp_type = (flags >> 4) & 7

        sys.stdout.write(" {:<16} ({:<7}, ".format(name, comp_str[comp_type]))

        if comp_type == 0x00 or comp_type == 0x02:
            sys.stdout.write("0x{:06x} - 0x{:06x}): "
                             .format(offset, offset + size))

            if name in unremovable_modules:
                end_addr = max(end_addr, offset + size)
                print("NOT removed, essential")
            else:
                end = min(offset + size, me_end)
                f.fill_range(offset, end, b"\xff")
                print("removed")

        elif comp_type == 0x01:
            sys.stdout.write("fragmented data    ): ")
            if not chunks_offsets:
                f.seek(offset)
                llut = f.read(4)
                if llut == b"LLUT":
                    llut += f.read(0x3c)

                    chunk_count = unpack("<I", llut[0x4:0x8])[0]
                    base = unpack("<I", llut[0x8:0xc])[0] + 0x10000000
                    chunk_size = unpack("<I", llut[0x30:0x34])[0]

                    llut += f.read(chunk_count * 4)
                    chunks_offsets = get_chunks_offsets(llut, me_start)
                else:
                    sys.exit("Huffman modules found, but LLUT is not present")

            if name in unremovable_modules:
                print("NOT removed, essential")
                module_base = unpack("<I", mod_header[0x34:0x38])[0]
                module_size = unpack("<I", mod_header[0x3c:0x40])[0]
                first_chunk_num = (module_base - base) // chunk_size
                last_chunk_num = first_chunk_num + module_size // chunk_size

                unremovable_huff_chunks += \
                    [x for x in chunks_offsets[first_chunk_num:
                     last_chunk_num + 1] if x[0] != 0]
            else:
                print("removed")

        else:
            sys.stdout.write("0x{:06x} - 0x{:06x}): unknown compression, "
                             "skipping".format(offset, offset + size))

    if chunks_offsets:
        removable_huff_chunks = []

        for chunk in chunks_offsets:
            if all(not(unremovable_chk[0] <= chunk[0] < unremovable_chk[1] or
                       unremovable_chk[0] < chunk[1] <= unremovable_chk[1])
                   for unremovable_chk in unremovable_huff_chunks):
                removable_huff_chunks.append(chunk)

        for removable_chunk in removable_huff_chunks:
            if removable_chunk[1] > removable_chunk[0]:
                end = min(removable_chunk[1], me_end)
                f.fill_range(removable_chunk[0], end, b"\xff")

        end_addr = max(end_addr,
                       max(unremovable_huff_chunks, key=lambda x: x[1])[1])

    return end_addr


def check_partition_signature(f, offset):
    f.seek(offset)
    header = f.read(0x80)
    modulus = int(binascii.hexlify(f.read(0x100)[::-1]), 16)
    public_exponent = unpack("<I", f.read(4))[0]
    signature = int(binascii.hexlify(f.read(0x100)[::-1]), 16)

    header_len = unpack("<I", header[0x4:0x8])[0] * 4
    manifest_len = unpack("<I", header[0x18:0x1c])[0] * 4
    f.seek(offset + header_len)

    sha256 = hashlib.sha256()
    sha256.update(header)
    sha256.update(f.read(manifest_len - header_len))

    decrypted_sig = pow(signature, public_exponent, modulus)

    return "{:#x}".format(decrypted_sig).endswith(sha256.hexdigest())   # FIXME


def relocate_partition(f, me_start, me_end, partition_header_offset,
                       new_offset, mod_headers):

    f.seek(partition_header_offset)
    name = f.read(4).rstrip(b"\x00").decode("ascii")
    f.seek(partition_header_offset + 0x8)
    old_offset, partition_size = unpack("<II", f.read(0x8))
    old_offset += me_start

    llut_start = 0
    for mod_header in mod_headers:
        if (unpack("<I", mod_header[0x50:0x54])[0] >> 4) & 7 == 0x01:
            llut_start = unpack("<I", mod_header[0x38:0x3C])[0] + old_offset
            break

    if llut_start != 0:
        # Bytes 0x9:0xb of the LLUT (bytes 0x1:0x3 of the AddrBase) are added
        # to the SpiBase (bytes 0xc:0x10 of the LLUT) to compute the final
        # start of the LLUT. Since AddrBase is not modifiable, we can act only
        # on SpiBase and here we compute the minimum allowed new_offset.
        f.seek(llut_start + 0x9)
        lut_start_corr = unpack("<H", f.read(2))[0]
        new_offset = max(new_offset,
                         lut_start_corr + me_start - llut_start - 0x40 +
                         old_offset)
        new_offset = ((new_offset + 0x1f) // 0x20) * 0x20

    offset_diff = new_offset - old_offset
    print("Relocating {} to {:#x} - {:#x}..."
          .format(name, new_offset, new_offset + partition_size))

    print(" Adjusting FPT entry...")
    f.write_to(partition_header_offset + 0x8,
               pack("<I", new_offset - me_start))

    if llut_start != 0:
        f.seek(llut_start)
        if f.read(4) == b"LLUT":
            print(" Adjusting LUT start offset...")
            lut_offset = llut_start + offset_diff + 0x40 - \
                         lut_start_corr - me_start
            f.write_to(llut_start + 0x0c, pack("<I", lut_offset))

            print(" Adjusting Huffman start offset...")
            f.seek(llut_start + 0x14)
            old_huff_offset = unpack("<I", f.read(4))[0]
            f.write_to(llut_start + 0x14,
                       pack("<I", old_huff_offset + offset_diff))

            print(" Adjusting chunks offsets...")
            f.seek(llut_start + 0x4)
            chunk_count = unpack("<I", f.read(4))[0]
            f.seek(llut_start + 0x40)
            chunks = bytearray(chunk_count * 4)
            f.readinto(chunks)
            for i in range(0, chunk_count * 4, 4):
                if chunks[i + 3] != 0x80:
                    chunks[i:i + 3] = \
                        pack("<I", unpack("<I", chunks[i:i + 3] +
                             b"\x00")[0] + offset_diff)[0:3]
            f.write_to(llut_start + 0x40, chunks)
        else:
            sys.exit("Huffman modules present but no LLUT found!")
    else:
        print(" No Huffman modules found")

    print(" Moving data...")
    partition_size = min(partition_size, me_end - old_offset)
    f.move_range(old_offset, partition_size, new_offset, b"\xff")

    return new_offset


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tool to remove as much code "
                                     "as possible from Intel ME/TXE firmwares")
    parser.add_argument("file", help="ME/TXE image or full dump")
    parser.add_argument("-O", "--output", help="save the modified image in a "
                        "separate file, instead of modifying the original "
                        "file")
    parser.add_argument("-r", "--relocate", help="relocate the FTPR partition "
                        "to the top of the ME region", action="store_true")
    parser.add_argument("-k", "--keep-modules", help="don't remove the FTPR "
                        "modules, even when possible", action="store_true")
    parser.add_argument("-d", "--descriptor", help="remove the ME/TXE "
                        "Read/Write permissions to the other regions on the "
                        "flash from the Intel Flash Descriptor (requires a "
                        "full dump)", action="store_true")
    parser.add_argument("-c", "--check", help="verify the integrity of the "
                        "fundamental parts of the firmware and exit",
                        action="store_true")
    args = parser.parse_args()

    f = open(args.file, "rb" if args.check or args.output else "r+b")
    f.seek(0x10)
    magic = f.read(4)

    if magic == b"$FPT":
        print("ME/TXE image detected")
        me_start = 0
        f.seek(0, 2)
        me_end = f.tell()

        if args.descriptor:
            sys.exit("-d requires a full dump")

    elif magic == b"\x5a\xa5\xf0\x0f":
        print("Full image detected")
        f.seek(0x14)
        flmap0, flmap1 = unpack("<II", f.read(8))
        nr = flmap0 >> 24 & 0x7
        frba = flmap0 >> 12 & 0xff0
        fmba = (flmap1 & 0xff) << 4
        if nr >= 2:
            f.seek(frba)
            flreg0, flreg1, flreg2 = unpack("<III", f.read(12))
            fd_start = (flreg0 & 0x1fff) << 12
            fd_end = flreg0 >> 4 & 0x1fff000 | 0xfff + 1
            me_start = (flreg2 & 0x1fff) << 12
            me_end = flreg2 >> 4 & 0x1fff000 | 0xfff + 1

            if me_start >= me_end:
                sys.exit("The ME/TXE region in this image has been disabled")

            f.seek(me_start + 0x10)
            if f.read(4) != b"$FPT":
                sys.exit("The ME/TXE region is corrupted or missing")

            print("The ME/TXE region goes from {:#x} to {:#x}"
                  .format(me_start, me_end))
        else:
            sys.exit("This image does not contains a ME/TXE firmware NR = {})"
                     .format(nr))
    else:
        sys.exit("Unknown image")

    print("Found FPT header at {:#x}".format(me_start + 0x10))

    f.seek(me_start + 0x14)
    entries = unpack("<I", f.read(4))[0]
    print("Found {} partition(s)".format(entries))

    f.seek(me_start + 0x14)
    header_len = unpack("B", f.read(1))[0]

    f.seek(me_start + 0x30)
    partitions = f.read(entries * 0x20)

    ftpr_header = b""

    for i in range(entries):
        if partitions[i * 0x20:(i * 0x20) + 4] == b"FTPR":
            ftpr_header = partitions[i * 0x20:(i + 1) * 0x20]
            break

    if ftpr_header == b"":
        sys.exit("FTPR header not found, this image doesn't seem to be valid")

    ftpr_offset, ftpr_lenght = unpack("<II", ftpr_header[0x08:0x10])
    ftpr_offset += me_start
    print("Found FTPR header: FTPR partition spans from {:#x} to {:#x}"
          .format(ftpr_offset, ftpr_offset + ftpr_lenght))

    f.seek(ftpr_offset)
    if f.read(4) == b"$CPD":
        me11 = True
        num_entries = unpack("<I", f.read(4))[0]
        ftpr_mn2_offset = 0x10 + num_entries * 0x18
    else:
        me11 = False
        ftpr_mn2_offset = 0

    f.seek(ftpr_offset + ftpr_mn2_offset + 0x24)
    version = unpack("<HHHH", f.read(0x08))
    print("ME/TXE firmware version {}"
          .format('.'.join(str(i) for i in version)))

    if not args.check:
        if args.output:
            f.close()
            shutil.copy(args.file, args.output)
            f = open(args.output, "r+b")

        mef = regionFile(f, me_start, me_end)

        print("Removing extra partitions...")
        mef.fill_range(me_start + 0x30, ftpr_offset, b"\xff")
        mef.fill_range(ftpr_offset + ftpr_lenght, me_end, b"\xff")

        print("Removing extra partition entries in FPT...")
        mef.write_to(me_start + 0x30, ftpr_header)
        mef.write_to(me_start + 0x14, pack("<I", 1))

        print("Removing EFFS presence flag...")
        mef.seek(me_start + 0x24)
        flags = unpack("<I", mef.read(4))[0]
        flags &= ~(0x00000001)
        mef.write_to(me_start + 0x24, pack("<I", flags))

        if args.descriptor:
            print("Removing ME/TXE R/W access to the other flash regions...")
            fdf = regionFile(f, fd_start, fd_end)
            fdf.write_to(fmba + 0x4, pack("<I", 0x04040000))

        if me11:
            mef.seek(me_start + 0x10)
            header = bytearray(mef.read(0x20))
        else:
            mef.seek(me_start)
            header = bytearray(mef.read(0x30))
        checksum = (0x100 - (sum(header) - header[0x1b]) & 0xff) & 0xff

        print("Correcting checksum (0x{:02x})...".format(checksum))
        # The checksum is just the two's complement of the sum of the first
        # 0x30 bytes in ME < 11 or bytes 0x10:0x30 in ME >= 11 (except for
        # 0x1b, the checksum itself). In other words, the sum of those bytes
        # must be always 0x00.
        mef.write_to(me_start + 0x1b, pack("B", checksum))

        if not me11:
            print("Reading FTPR modules list...")
            mef.seek(ftpr_offset + 0x1c)
            tag = mef.read(4)

            if tag == b"$MN2":
                mef.seek(ftpr_offset + 0x20)
                num_modules = unpack("<I", mef.read(4))[0]
                mef.seek(ftpr_offset + 0x290)
                data = mef.read(0x84)

                module_header_size = 0
                if data[0x0:0x4] == b"$MME":
                    if data[0x60:0x64] == b"$MME" or num_modules == 1:
                        module_header_size = 0x60
                    elif data[0x80:0x84] == b"$MME":
                        module_header_size = 0x80

                if module_header_size != 0:
                    mef.seek(ftpr_offset + 0x290)
                    mod_headers = [mef.read(module_header_size)
                                   for i in range(0, num_modules)]

                    if all(hdr.startswith(b"$MME") for hdr in mod_headers):
                        if args.keep_modules:
                            end_addr = ftpr_offset + ftpr_lenght
                        else:
                            end_addr = remove_modules(mef, mod_headers,
                                                      ftpr_offset, me_end)

                        if args.relocate:
                            new_ftpr_offset = relocate_partition(mef,
                                               me_start, me_end,
                                               me_start + 0x30,
                                               min_ftpr_offset + me_start,
                                               mod_headers)
                            end_addr += new_ftpr_offset - ftpr_offset
                            ftpr_offset = new_ftpr_offset

                        end_addr = (end_addr // 0x1000 + 1) * 0x1000
                        end_addr += spared_blocks * 0x1000

                        print("The ME minimum size should be {0} bytes "
                              "({0:#x} bytes)".format(end_addr - me_start))

                        if me_start > 0:
                            print("The ME region can be reduced up to:\n"
                                  " {:08x}:{:08x} me"
                                  .format(me_start, end_addr - 1))
                    else:
                        print("Found less modules than expected in the FTPR "
                              "partition; skipping modules removal")
                else:
                    print("Can't find the module header size; skipping "
                          "modules removal")
            else:
                print("Wrong FTPR partition tag ({}); skipping modules removal"
                      .format(tag))
        else:
            print("Modules removal in ME v11 or greater is not yet supported")

    sys.stdout.write("Checking FTPR RSA signature... ")
    if check_partition_signature(f, ftpr_offset + ftpr_mn2_offset):
        print("VALID")
    else:
        print("INVALID!!")
        sys.exit("The FTPR partition signature is not valid. Is the input "
                 "ME/TXE image valid?")

    f.close()

    if not args.check:
        print("Done! Good luck!")
