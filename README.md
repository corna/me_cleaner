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

| PCH           | CPU           | ME | SKU      | Status		 |
|:-------------:|:-------------:|:---|:--------:|:---------:|
| Ibex Peak     | Nehalem       | 6.0 | Ignition | **WORKS** |
| Ibex Peak     | Nehalem       | 6.x | 1.5/5MB	 | DOESN'T WORK (yet) |
| Cougar Point  | Sandy Bridge	| 7.x | 1.5/5MB  | **WORKS** |
| Panther Point | Ivy Bridge	  | 8.x | 1.5/5MB  | **WORKS** |
| Lynx/Wildcat Point   | Haswell/Broadwell       | 9.x | 1.5/5MB	 | UNTESTED |
| Wildcat  Point LP   | Broadwell Mobile	    | 10.0 | 1.5/5MB  | UNTESTED |
| Sunrise Point | Skylake/Kabylake	      | 11.x | CON/COR  | **WORKS** |
| Union Point   | Kabylake	    | 11.6 | CON/COR  | UNTESTED |

Special thanks to Federico Amedeo Izzo for his help during the study of Intel
ME.

