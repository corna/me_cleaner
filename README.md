# ME cleaner

A cleaner for Intel ME images.

This tools removes any unnecessary partition from an Intel ME firmware, reducing
its size and its ability to interact with the system.
It should work both with Coreboot and with the factory BIOS.

Currently this tool:
 * Scans the FPT (partition table) and checks that everything is correct
 * Removes any partition entry (except for FTPR) from FPT
 * Removes any partition except for the fundamental one (FTPR)
 * Corrects the FPT checksum

Don't forget to power cycle your PC after flashing the modified ME image (power
off and power on, not just reboot).

Current status:

| PCH           | CPU           | SKU      | Status		 |
|:-------------:|:-------------:|:--------:|:---------:|
| Ibex Peak     | Nehalem       | Ignition | **WORKS** |
| Ibex Peak     | Nehalem       | 1.5/5MB	 | DOESN'T WORK (yet) |
| Cougar Point  | Sandy Bridge	| 1.5/5MB  | **WORKS** |
| Panther Point | Ivy Bridge	  | 1.5/5MB  | **WORKS** |
| Lynxt Point   | Haswell       | 1.5/5MB	 | UNTESTED |
| Lynxt Point   | Broadwell	    | 1.5/5MB  | UNTESTED |
| Sunrise Point | Skylake	      | CON/COR  | **WORKS** |
| Union Point   | Kabylake	    | CON/COR  | UNTESTED |

Special thanks to Federico Amedeo Izzo for his help during the study of Intel
ME.

