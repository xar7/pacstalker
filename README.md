
# Table of Contents

1.  [Pacstalker](#orgc65b6d5)
    1.  [Description](#org33c4479)
    2.  [How to](#org5cdc640)
        1.  [Build](#org9ab7834)
        2.  [Run the script](#org95a5bd5)
        3.  [Use](#org3c20303)


<a id="orgc65b6d5"></a>

# Pacstalker


<a id="org33c4479"></a>

## Description

Pacstalker is a simple tool capable of determinating a estimated size of the data transferred during a tls/ssl session which was recorded on a pcap file.
This repository also provide a python script that is actually a wrapper around the C-written binary, this script aims at determinating which archlinux package was downloaded during a recorded tls/ssl session.


<a id="org5cdc640"></a>

## How to


<a id="org9ab7834"></a>

### Build

In order to build the binary, please just run `make`. You can of course clean the produced files afterward (and delete the binary) by using `make clean`.


<a id="org95a5bd5"></a>

### Run the script

I used pipenv for the python script dependencies, to install the python packages needed by `pacstalker.py` just run `pipenv install` and then `pipenv shell` will bring you to the virtual env allowing you to use the script without problems.


<a id="org3c20303"></a>

### Use

If you just want to use the C-binary to determinate the a estimated size of encrypted data transferred on a record, type : `/bin/pacstalker <yourpcap>`.

If you want to guess which archlinux-package was downloaded from a pcap file, you will first have to get to the pipenv shell and then run `python pacstalker.py <yourpcap>`.
Some options are available, please use the `--help` options to learn about them.

