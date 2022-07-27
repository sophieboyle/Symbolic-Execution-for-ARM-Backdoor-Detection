# L4-Project: Static Analysis of Executable Code to Detect Backdoors in IoT Devices

This is a python tool which leverages the symbolic execution capabilities of [Angr](https://github.com/angr/angr) in order to find indicators of backdoors in binaries. The current indicators which have modules written to detect them are as follows:

- Networking activity
- Shell commands
- File accesses

## Build Instructions

### Requirements

- Python3 == 3.9.13
- Python packages can be installed via the `requirements.txt` file

Note that these requirements have been tested on Ubuntu 22 and Windows 10.

### Build Steps

- Install required packages: `requirements.txt`
- Run the tool: `python3 -m src.main <path-to-32bit-ARM-binary>`

### Test Steps

- Run the tests via python unittest suite: `python3 -m unittest`
- Tests assume that the default `bad-ips.csv`, `bad-ports.csv`, and `sensitive-files.csv` have been un-edited
