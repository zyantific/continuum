continuum
=========

continuum is an IDA Pro plugin adding multi-binary project support, 
allowing fast navigation in applications involving many shared libraries.

**This project is still work in progress and not suitable for production use.**

## Features
- Quick navigation between many IDA instances
  - Project explorer widget in IDA's "sidebar"
  - Pressing `SHIFT + F` on an `extrn` symbol navigates to the instance where the symbol is defined
  - If required, new IDA instances are automatically spawned for IDBs with no instance open
- Type information is synchronized between all IDBs in a project (beta)

## Screenshots
![Project creation](https://raw.githubusercontent.com/zyantific/continuum/master/media/project-creation.png)
![Project explorer](https://raw.githubusercontent.com/zyantific/continuum/master/media/project-explorer.png)

## Requirements
- IDA >= 6.9
- IDAPython (ships with IDA)

All operating systems supported by IDA are also supported by this plugin. 
Lacking licenses for Linux and OSX, it hasn't been tested on these platforms, yet.

## Installation
Place the `continuum` directory and `continuum_ldr.py` into the `plugins` directory of your IDA installation.
