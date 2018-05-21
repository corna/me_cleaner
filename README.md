# me\_cleaner [![Donation](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=B5HCXCLZVCVZ8)

_me\_cleaner_ is a Python script able to modify an Intel ME firmware image with
the final purpose of reducing its ability to interact with the system.

## Intel ME

Intel ME is a co-processor integrated in all post-2006 Intel boards, which is
the base hardware for many Intel features like Intel AMT, Intel Boot Guard,
Intel PAVP and many others. To provide such features, it requires full access to
the system, including memory (through DMA) and network access (transparent to
the user).

Unlike many other firmware components, the Intel ME firmware can't be neither
disabled nor reimplemented, as it is tightly integrated in the boot process and
it is signed.

This poses an issue both to the free firmware implementations like [coreboot](
https://www.coreboot.org/), which are forced to rely on a proprietary, obscure
and always-on blob, and to the privacy-aware users, who are reasonably worried
about such firmware, running on the lowest privilege ring on x86.

## What can be done

Before Nehalem (ME version 6, 2008/2009) the ME firmware could be removed
completely from the flash chip by setting a couple of bits inside the flash
descriptor, effectively disabling it.

Starting from Nehalem the Intel ME firmware can't be removed anymore: without a
valid firmware the PC shuts off forcefully after 30 minutes, probably as an
attempt to enforce the Intel Anti-Theft policies.

However, while Intel ME can't be turned off completely, it is still possible to
modify its firmware up to a point where Intel ME is active only during the boot
process, effectively disabling it during the normal operation, which is what
_me\_cleaner_ tries to accomplish.

## Platform support

_me\_cleaner_ currently works on [most of the Intel platforms](
https://github.com/corna/me_cleaner/wiki/me_cleaner-status); while this doesn't
mean it works on all the boards (due to the different firmware implementations),
it has been proven quite reliable on a great number of them.

## Usage

_me\_cleaner_ should handle all the steps necessary to the modification of an
Intel ME firmware with the command:

      $ python me_cleaner.py -S -O modified_image.bin original_dump.bin

However, obtaining the original firmware and flashing back the modified one is
usually not trivial, as the Intel ME firmware region is often non-writable from
the OS (and it's not a safe option anyways), requiring the use of an external
SPI programmer.

## Results

For generation 1 (before Nehalem, ME version <= 5) this tool removes the whole
ME firmware and disables it completely.

For generation 2 (Nehalem-Broadwell, ME version between 6 and 10) this tool
removes almost everything, leaving only the two fundamental modules needed for
the correct boot, `ROMP` and `BUP`. The firmware size is reduced from 1.5 MB
(non-AMT firmware) or 5 MB (AMT firmware) to ~90 kB.

For generation 3 (from Skylake onwards, ME version >= 11) the ME subsystem and
the firmware structure have changed, requiring substantial changes
in _me\_cleaner_. The fundamental modules required for the correct boot are now
four (`rbe`,  `kernel`, `syslib` and `bup`) and the minimum firmware size is
~300 kB (from the 2 MB of the non-AMT firmware and the 7 MB of the AMT one).

On some boards the OEM firmware fails to boot without a valid Intel ME firmware;
in the other cases the system should work with minor inconveniences (like longer
boot times or warning messages) or without issues at all.

Obviously, the features provided by Intel ME won't be functional anymore after
the modifications.

## Documentation

The detailed documentation about the working of _me\_cleaner_ can be found on
the page ["How does it work?" page](
https://github.com/corna/me_cleaner/wiki/How-does-it-work%3F).

Various guides and tutorials are available on the Internet, however a good
starting point is the ["How to apply me_cleaner" guide](
https://github.com/corna/me_cleaner/wiki/How-to-apply-me_cleaner).

