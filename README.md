# PCRT (PNG Check & Repair Tool)
[![Python 2.7](https://img.shields.io/badge/Python-2.7-blue.svg)](https://www.python.org/downloads/) 
[![Version 1.1](https://img.shields.io/badge/Version-1.1-brightgreen.svg)]() 

## Description

**PCRT** (PNG Check & Repair Tool) is a tool to help check if PNG image correct and try to auto fix the error. It's cross-platform, which can run on **Windows**, **Linux** and **Mac OS**. 

It can:

	Show image information
	Fix PNG header error
	Fix wrong IHDR chunk crc due to error picture's width or height
	Fix wrong IDAT chunk data length due to DOS->UNIX conversion
	Fix wrong IDAT chunk crc due to its own error
	Fix lost IEND chunk
	Extract data after IEND chunk (Malware programs like use this way to hide)
	Show the repaired image
	Inject payload into image
	Decompress image data and show the raw image
	...
	Maybe more in the future :)  


## Install

- #### **Install Python 3.11**

- #### **Install Python dependency packages**
	- [PIL](https://pypi.python.org/pypi/PIL)


- #### **Clone the source code**

		git clone https://github.com/sherlly/PCRT.git
		cd PCRT
		python PCRT.py

## Usage

	> python PCRT.py -h
	usage: PCRT.py [-h] [-q] [-y] [-v] [-m] [-n NAME] [-p PAYLOAD] [-w WAY]
                 [-d DECOMPRESS] [-i INPUT] [-f] [-o OUTPUT]

	optional arguments:
    -h, --help            show this help message and exit
    -q, --quiet           don't show the banner infomation
    -y, --yes             auto choose yes
    -v, --verbose         use the safe way to recover
    -m, --message         show the image information
    -n NAME, --name NAME  payload name [Default: random]
    -p PAYLOAD, --payload PAYLOAD
                          payload to hide
    -w WAY, --way WAY     payload chunk: [1]: ancillary [2]: critical
                          [Default:1]
    -d DECOMPRESS, --decompress DECOMPRESS
                          decompress zlib data file name
    -i INPUT, --input INPUT
                          Input file name (*.png) [Select from terminal]
    -f, --file            Input file name (*.png) [Select from window]
    -o OUTPUT, --output OUTPUT
                          Output repaired file name [Default: output.png]

**[Notice]** without `-v` option means that assume all IDAT chunk length are correct


## Show

- Window:

![](http://i.imgur.com/Ksk2ctV.png)

- Linux:

![](http://i.imgur.com/ZXnPqYD.png)

- Mac OS:

![](http://i.imgur.com/re4gQux.png)

## Some Problem:

- For Window:

> Can't show the repaired image

1. Find the file named `ImageShow.py` under the path like `X:\Python27\lib\site-packages\PIL\ImageShow.py`
2. Find the code `return "start /wait %s && ping -n 2 127.0.0.1 >NUL && del /f %s" % (file, file)` around line 100 and commented it
3. Add the new code: `return "start /wait %s && PING 127.0.0.1 -n 5 > NUL && del /f %s" % (file, file)` and save
4. Restart the python IDE

## Release Log

### version 1.1:


**Add：**

- Show image information (`-m`)
- Inject payload into image (`-p`)
	- add into ancillary chunk (chunk name can be randomly generated or self-defined) (`-w 1`)
	- add into critical chunk (only support IDAT chunk) (`-w 2`)
- decompress image data and show the raw image (`-d`)

### version 1.0：

**Feature:**

- Fix PNG header error
- Fix wrong IHDR chunk crc due to error picture's width or height
- Fix wrong IDAT chunk data length due to DOS->UNIX conversion
- Fix wrong IDAT chunk crc due to its own error
- Fix lost IEND chunk
- Extract data after IEND chunk (Malware programs like use this way to hide)
- Show the repaired image
---
