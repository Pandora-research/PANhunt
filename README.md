PANhunt
========

##Introduction

PANhunt is a tool that can be used to search drives for credit card numbers (PANs). This is useful for checking PCI DSS scope accuracy. It's designed to be a simple, standalone tool that can be run from a USB stick.

## Build

PANhunt is a Python script that can be easily converted to a standalone Windows executable using PyInstaller.

panhunt.py requires:

	- Python 2.7
	- Colorama (https://pypi.python.org/pypi/colorama)
	- Progressbar (https://pypi.python.org/pypi/progressbar)
	- Python-docx (https://pypi.python.org/pypi/python-docx)
	- docx2txt (https://pypi.python.org/pypi/docx2txt)
	- Pdfminer (https://pypi.python.org/pypi/pdfminer)
	- Pdfquery (https://pypi.python.org/pypi/pdfquery)
	- PyODBC (http://www.lfd.uci.edu/~gohlke/pythonlibs/#pyodbc)
	- PyInstaller (https://pypi.python.org/pypi/PyInstaller)

To create panhunt.exe as a standalone executable with an icon run:

```
pyinstaller.exe panhunt.py -F -i dionach.ico
```	

##Usage

```
usage: panhunt [-h] [-s SEARCH] [-x EXCLUDE] [-t TEXTFILES] [-z ZIPFILES] [-e SPECIALFILES] [-m MAILFILES] [-l OTHERFILES] [-o OUTFILE] [-u]

PAN Hunt v1.1: search directories and sub directories for documents containing PANs.

optional arguments:
  -h, --help       show this help message and exit
  -s SEARCH        base directory to search in (default: C:\)
  -x EXCLUDE       directories to exclude from the search (default: C:\Windows,C:\Program Files,C:\Program Files (x86))
  -t TEXTFILES     text file extensions to search (default: .doc,.xls,.xml,.txt,.csv,.log,.tmp,.bak,.rtf,.csv,.htm,.html)
  -z ZIPFILES      zip file extensions to search (default: .docx,.xlsx,.zip)
  -e SPECIALFILES  special file extensions to search (default: .msg,.pdf)
  -m MAILFILES     email file extensions to search (default: .pst)
  -l OTHERFILES    other file extensions to list (default: .ost,.accdb,.mdb)
  -o OUTFILE       output file name for PAN report (default: panhunt_YYYY-MM-DD-HHMMSS.txt)
  -u               unmask PANs in output (default: False)
```

Simply running it with no arguments will search the C:\ drive for documents containing PANs, and output to panhunt_<timestamp>.txt.

##Example Output

```
Doc Hunt: 100% ||||||||||||||||||||||||||||||||||||||||| Time: 0:00:01 Docs:299
PAN Hunt: 100% |||||||||||||||||||||||||||||||||||||||||| Time: 0:00:02 PANs:99
FOUND PANs: D:\lab\Archive Test Cards.zip (21KB 19/02/2014)
        Archived Test Cards Excel 97-2003.xls AMEX:***********0005
        Archived Test Cards Excel 97-2003.xls AMEX:***********8431
		...
FOUND PANs: D:\lab\Archived Test Cards Word 2010.docx (19KB 18/02/2014)
        word/document.xml Visa:************1111
        word/document.xml Visa:************1881
        word/document.xml Visa:************1111
        word/document.xml Visa:************0000
		...
FOUND PANs: D:\lab\test card text file.txt (47B 26/02/2014)
         Visa:************1111
         Visa:****-****-****-1111
		...
Report written to panhunt_YYYY-MM-DD-HHMMSS.txt
```

## Function

The script uses regular expressions to look for Visa, MasterCard or AMEX credit card numbers in document files. Zip files are recursed to look for document files. PST and MSG files are parsed and emails and attachments searched in. The script will list but does not yet search Access databases.
