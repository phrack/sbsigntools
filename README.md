sbsigntool - Signing utility for UEFI secure boot

  Copyright (C) 2102 Jeremy Kerr <jeremy.kerr@canonical.com>

  Copying and distribution of this file, with or without modification,
  are permitted in any medium without royalty provided the copyright
  notice and this notice are preserved.

See file ./INSTALL for building and installation instructions.

Main git repository:
  git://kernel.ubuntu.com/jk/sbsigntool.git

sbsigntool is free software.  See the file COPYING for copying conditions.


This is a fork of sbsigntools to fix issues preventing the use of the tools -- particularly sbsign -- with Amazon's CloudHSM, and likely other HSMs:

1. sbsigntools intentionally does not allow the use of dynamic engines. This eliminates the risk that a malicous engine will be loaded. Solution: Accept the risk and change the code to allow dynamic engines.
2. sbsigntools assumes keys are in an engine form when an engine is specified. This does not work for HSMs that use a safety key design -- where a "fake" key is stored in a file outside of the HSM, and this key is mapped to the real key in the HSM for cryptographic operations performed by the HSM. Solution: Add a new optional switch to specify the keyform and add PEM for use with safety keys and an engine.
3. sbsigntools does not initialize OpenSSL engines with all methods, which prevents HSMs that use a safety key from mapping the key. Solution: Alter the code to initialize OpenSSL engines with all methods. 
4. sbsigntools loads an OpenSSL engine right before loading a key, then immediately closes the engine. Thus, the engine is not available for mapping when the key is used. Solution: Alter the code to ensure an engine specified on the command line is available throughout a tool's execution.

To sign a Linux kernel using a key stored in AWS CloudHSM:

A. Generate a PKI suitable for UEFI code signing as usual using the openssl commands, but be sure to add the switch: -engine cloudhsm
B. Specify the new switch --keyform that this fork adds when using sbsign: sbsign --engine cloudhsm --key <keyfile> --keyform PEM --cert <cert> <kernelfile>
