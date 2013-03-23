Panoptic v0.1
===

Scan systems for default file locations

### Help Menu
    Usage: panoptic.py --url TARGET [options]

	Options:
  	  -h, --help            show this help message and exit
  	  -u TARGET, --url=TARGET
                        	set the target to test
  	  -p PARAM, --param=PARAM
                        	set the parameter to test
  	  -d DATA, --data=DATA  set data for POST request
  	  -o OS, --os=OS        set an operating system to limit searches to
  	  -s SOFTWARE, --software=SOFTWARE
                        	set the name of the software to search for
  	  -c CATEGORY, --category=CATEGORY
                        	set a specific category of software to look for
  	  -t CLASSIFICATION, --type=CLASSIFICATION
                        	set the type of file to search for (conf or log)
  	  -b PREFIX, --prefix=PREFIX
                        	set a prefix for file path (i.e. "../")
  	  -e POSTFIX, --postfix=POSTFIX
                        	set a prefix for file path (i.e. "%00")
  	  -m MULTIPLIER, --multiplier=MULTIPLIER
                        	set a number to multiply the prefix by
  	  -w, --write-file      write all found files to output folder
  	  -l LIST, --list=LIST  list the available filters ("os", "category", "software")
  	  -v, --verbose         display extra information in the output

### Examples
    ./panoptic.py --help

    ./panoptic.py --url http://localhost/lfi.php?file=test.txt
	./panoptic.py --url http://localhost/lfi.php?file=test.txt&id=1 --param file
	./panoptic.py --url http://localhost/lfi.php --data "file=test.txt&id=1" --param file

	./panoptic.py --list software
	./panoptic.py --list category
	./panoptic.py --list os

	./panoptic.py --url http://localhost/lfi.php?file=test.txt --os Windows
	./panoptic.py --url http://localhost/lfi.php?file=test.txt --software WAMP

    ./panoptic.py --url http://localhost/lfi.php?file=test.txt --verbose --write-file
	./panoptic.py --url http://localhost/lfi.php?file=test.txt --prefix "../" --multiplier 4 --postfix "%00"


