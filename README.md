# ME cleaner

A cleaner for Intel ME images.

This tools removes any unnecessary partition from an Intel ME firmware, reducing
its size and its ability to interact with the system.
It should work both with Coreboot and with the factory BIOS.

Currently this tool:
 * Scans the FPT (partition table) and checks that everything is correct
 * Removes any partition entry (except for FTPR) from FPT
 * Removes any partition except for the fundamental one (FTPR)
 * Removes the EFFS presence flag
 * Removes any LZMA-compressed module
 * Corrects the FPT checksum

Don't forget to power cycle your PC after flashing the modified ME image (power
off and power on, not just reboot).

See the current status [in the wiki](https://github.com/corna/me_cleaner/wiki/me_cleaner-status).

Special thanks to Federico Amedeo Izzo for his help during the study of Intel
ME.
