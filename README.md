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

Current status:

| PCH           | CPU           | SKU      | Status		 |
|:-------------:|:-------------:|:--------:|:---------:|
| Ibex Peak     | Nehalem       | Ignition | **WORKS** |
| Ibex Peak     | Nehalem       | 1.5/5MB	 | DOESN'T WORK (yet) |
| Cougar Point  | Sandy Bridge	| 1.5/5MB  | UNTESTED |
| Panther Point | Ivy Bridge	  | 1.5/5MB  | **WORKS** |
| Lynxt Point   | Haswell       | 1.5/5MB	 | UNTESTED |
| Lynxt Point   | Broadwell	    | 1.5/5MB  | UNTESTED |
| Sunrise Point | Skylake	      | CON/COR  | UNTESTED |
| Union Point   | Kabylake	    | CON/COR  | UNTESTED |
