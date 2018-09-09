[//]: # (Use md2man to generate the man page from this Markdown)
[//]: # (https://github.com/sunaku/md2man)

me_cleaner 1 "JUNE 2018"
=======================================

me\_cleaner
----

me\_cleaner -  Tool for partial deblobbing of Intel ME/TXE firmware images 

SYNOPSIS
--------

`me_cleaner.py` [-h] [-v] [-O output\_file] [-S | -s] [-r] [-k]
[-w whitelist | -b blacklist] [-d] [-t] [-c] [-D output\_descriptor]
[-M output\_me\_image] *file*

DESCRIPTION
-----------

`me_cleaner` is a tool able to disable parts of Intel ME/TXE by:

 * removing most of the code from its firmware
 * setting a special bit to force it to disable itself after the hardware
initialization

Using both the modes seems to be the most reliable way on many platforms.

The resulting modified firmware needs to be flashed (in most of the cases) with
an external programmer, often a dedicated SPI programmer or a Linux board with
a SPI master interface.

`me_cleaner` works at least from Nehalem to Coffee Lake (for Intel ME) and on
Braswell/Cherry Trail (for Intel TXE), but may work as well on newer or
different architectures.

While `me_cleaner` have been tested on a great number of platforms, fiddling
with the Intel ME/TXE firmware is *very dangerous* and can easily lead to a
dead PC.

*YOU HAVE BEEN WARNED.*

POSITIONAL ARGUMENTS
--------------------

`file`
  ME/TXE image or full dump.

OPTIONAL ARGUMENTS
------------------

`-h`, `--help`
  Show the help message and exit.

`-v`, `--version`
  Show program's version number and exit.

`-O`, `--output`
  Save the modified image in a separate file, instead of modifying the
  original file.

`-S`, `--soft-disable`
  In addition to the usual operations on the ME/TXE firmware, set the
  MeAltDisable bit or the HAP bit to ask Intel ME/TXE to disable itself after
  the hardware initialization (requires a full dump).

`-s`, `--soft-disable-only`
  Instead of the usual operations on the ME/TXE firmware, just set the
  MeAltDisable bit or the HAP bit to ask Intel ME/TXE to disable itself after
  the hardware initialization (requires a full dump).

`-r`, `--relocate`
  Relocate the FTPR partition to the top of the ME region to save even more
  space.

`-t`, `--truncate`
  Truncate the empty part of the firmware (requires a separated ME/TXE image or
  `--extract-me`).

`-k`, `--keep-modules`
  Don't remove the FTPR modules, even when possible.

`-w`, `--whitelist`
  Comma separated list of additional partitions to keep in the final image.
  This can be used to specify the MFS partition for example, which stores PCIe
  and clock settings.

`-b`, `--blacklist`
  Comma separated list of partitions to remove from the image. This option
  overrides the default removal list.

`-d`, `--descriptor`
  Remove the ME/TXE Read/Write permissions to the other regions on the flash
  from the Intel Flash Descriptor (requires a full dump).

`-D`, `--extract-descriptor`
  Extract the flash descriptor from a full dump; when used with `--truncate`
  save a descriptor with adjusted regions start and end.

`-M`, `--extract-me`
  Extract the ME firmware from a full dump; when used with `--truncate` save a
  truncated ME/TXE image.

`-c`, `--check`
  Verify the integrity of the fundamental parts of the firmware and exit.

SUPPORTED PLATFORMS
-------------------

Currently `me_cleaner` has been tested on the following platforms:

| PCH               | CPU               | ME   | SKU      |
|:-----------------:|:-----------------:|:----:|:--------:|
| Ibex Peak         | Nehalem/Westmere  | 6.0  | Ignition |
| Ibex Peak         | Nehalem/Westmere  | 6.x  | 1.5/5 MB |
| Cougar Point      | Sandy Bridge      | 7.x  | 1.5/5 MB |
| Panther Point     | Ivy Bridge        | 8.x  | 1.5/5 MB |
| Lynx/Wildcat Point| Haswell/Broadwell | 9.x  | 1.5/5 MB |
| Wildcat  Point LP | Broadwell Mobile	| 10.0 | 1.5/5 MB |
| Sunrise Point     | Skylake/Kabylake	| 11.x | CON/COR  |
| Union Point       | Kabylake	        | 11.x | CON/COR  |

| SoC                   | TXE | SKU      |
|:---------------------:|:---:|:--------:|
| Braswell/Cherry Trail | 2.x | 1.375 MB |

All the reports are available on the [project's GitHub page](
https://github.com/corna/me_cleaner/issues/3).

EXAMPLES
--------

Check whether the provided image has a valid structure and signature:

  `me_cleaner.py -c dumped_firmware.bin`

Remove most of the Intel ME firmware modules but don't set the HAP/AltMeDisable
bit:

  `me_cleaner.py -S -O modified_me_firmware.bin dumped_firmware.bin`

Remove most of the Intel ME firmware modules and set the HAP/AltMeDisable bit,
disable the Read/Write access of Intel ME to the other flash region, then
relocate the code to the top of the image and truncate it, extracting a modified
descriptor and ME image:

  `me_cleaner.py -S -r -t -d -D ifd_shrinked.bin -M me_shrinked.bin -O modified_firmware.bin full_dumped_firmware.bin`

BUGS
----

Bugs should be reported on the [project's GitHub page](
https://github.com/corna/me_cleaner).

AUTHOR
------

Nicola Corna <nicola@corna.info>

SEE ALSO
--------

flashrom(8), [me\_cleaner's Wiki](https://github.com/corna/me_cleaner/wiki)
