# Pacstalker


## Description

Pacstalker is a simple tool capable of determinating a estimated size of the data transferred during a tls/ssl session which was recorded on a pcap file.
This repository also provide a python script that is actually a wrapper around the C-written binary, this script aims at determinating which archlinux package was downloaded during a recorded tls/ssl session.


## How to


### Build

In order to build the binary, please just run `make`. You can of course clean the produced files afterward (and delete the binary) by using `make clean`.


### Run the script

I used pipenv for the python script dependencies, to install the python packages needed by `pacstalker.py` just run `pipenv install` and then `pipenv shell` will bring you to the virtual env allowing you to use the script without problems.


### Use

If you just want to use the C-binary to determinate the a estimated size of encrypted data transferred on a record, type : `bin/pacstalker <yourpcap>`.

If you want to guess which archlinux-package was downloaded from a pcap file, you will first have to get to the pipenv shell and then run `python pacstalker.py <yourpcap>`.
Some options are available, please use the `--help` option to learn about them.

