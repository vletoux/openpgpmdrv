# OpenPGP minidriver

A minidriver for the OpenPGP card.

These project should be considered in addition to the [OpenPGP CSP project](https://github.com/vletoux/OpenPGP-CSP).

It has been designed to provide support for the OpenPGP card.

## Getting Started

Open the solution in Visual Studio and build the project.
The version used for the development is Visual Studio 2012

### Prerequisites

The current release is signed by a SHA2 certificate (kernel mode signing).
That means that the [Microsoft Security Advisory 3033929](https://docs.microsoft.com/en-us/security-updates/securityadvisories/2015/3033929) MUST be installed.

## Running the tests

Run certutil -scinfo (beware of the 32 or 64 bits version when doing test - c:\windows\syswow64\certutil.exe is the 32 bits one)
and double check that the Card name is filled.

### Certutil test with the "Open PGP Card v2"



```
  0: SCM Microsystems Inc. SCR33x USB Smart Card Reader 0
--- Lecteur�: SCM Microsystems Inc. SCR33x USB Smart Card Reader 0
--- Statut�: SCARD_STATE_PRESENT | SCARD_STATE_UNPOWERED
--- Statut�: Carte disponible pour utilisation.
---   Carte�: OpenPGP
---    ATR�:
        3b da 18 ff 81 b1 fe 75  1f 03 00 31 c5 73 c0 01   ;......u...1.s..
        40 00 90 00 0c                                     @....
```

## Authors

* **Vincent LE TOUX** - *Initial commit*

## License

This project is licensed under the LGPL License

