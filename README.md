# NewDomainSpotter

Download a list of newly registered domains and spot suspicious domains which may
be indicative of phishing, or other malicious purposes.

## Usage

NewDomainSpotter supports the following:

```bash
newdomainspotter.py -h
Examples:
         python newdomainspotter.py -r 'google'
         python newdomainspotter.py -a 'microsoft'

optional arguments:
  -h, --help            show this help message and exit
  -r RFUZZ, --rfuzz RFUZZ
                        Identify similar domains with a single keyword useing RapidFuzz
  -a, --all             Generic single keyword search, mimics Ctrl+F functionaility

