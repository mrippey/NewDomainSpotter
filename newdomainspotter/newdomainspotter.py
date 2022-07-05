AUTHOR = "Michael Rippey, Twitter: @nahamike01"
LAST_SEEN = "2022 07 05"
DESCRIPTION = """Download/search for suspicious domains from the WHOISDS database. 

usage: python3 newdomainspotter.py -rfuzz <<str(keyword)>>  || -a <<str(keyword)>>"""

import os
import sys
import argparse
import base64
from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path
import requests
from typing import List, Tuple
from zipfile import ZipFile
import re

try:
    from rapidfuzz import process
except ImportError:
    print('rapidfuzz not installed, use:')
    print('\t\tpip3 install rapidfuzz')


WHOISDS_URL = "https://whoisds.com//whois-database/newly-registered-domains/"

regex_for_domain_names = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}'


def format_date_url() -> str:
    """
    Set date to yesterday"s date in
    Args: None  
    Returns: 
    str -> Yesterday"s date Base64 encoded with additional information for URL
    """
    yesterday = datetime.now() - timedelta(days=2)
    format_date = datetime.strftime(yesterday, "%Y-%m-%d")
    url_add_ext = f"{format_date}.zip"
    finished_url_date = base64.b64encode(url_add_ext.encode("utf-8")).decode("utf-8")
    return finished_url_date


def get_newreg_domains() -> requests.Response:
    """
    Fetch content from WHOISDS website for new domains file 
    Args: None 
    Returns: 
    requests.Response -> Content of server response
    (zip file of newly registered domains)
    """
    add_date_url = format_date_url()

    try:
        print('[+] Connecting to WHOISDS...\n')
        headers = {"User-Agent": "NewDomainSpotter v0.2 (github: @mrippey"}
        whoisds_new_domains = requests.get(WHOISDS_URL + add_date_url + "/nrd", headers=headers)
        whoisds_new_domains.raise_for_status()

    except requests.RequestException as err:
        print(f"[!] Requests Module Exception: {err}")

    return whoisds_new_domains.content


def process_domain_file() -> List[str]:
    """
    Open and read returned zip file from request 
    Args: None 
    Returns: 
    List[str] -> The zip file is read and returns each newly 
    identified domain as a list of strings.
    """
    domain_file = get_newreg_domains()
    domains = []

    try:
        print('[+] Processing list of newly registered domains...\n')
        with ZipFile(BytesIO(domain_file)) as data:

            for info in data.infolist():
                with data.open(info) as lines:
                    for line in lines:

                        file = line.decode("ascii")
                        domains.append(str(file).rstrip("\r\n"))

    except ZipFile.BadZipFile as err:
        print(f"[!] Exception: {err}")

    return domains


def rapidfuzz_multi_query(results_file) -> List[Tuple]:
    """
    Return RapidFuzz string match of search query 
    Args: query_str 
    Returns: 
    List[Tuple] -> Best matches based on similarity
    """
    paths = [] 

    with open('./queries.txt', 'r')as data:
        query_str = data.readlines()

    paths = [uri_path.strip() for uri_path in query_str]

    #print(paths)
    
    new_domains_list = process_domain_file()

    for query in paths:
        results = process.extract(query, new_domains_list)
        domain_matches = ", '".join(map(str, results))
        domain_matches.replace("'", '')

        #print(domain_matches)
        with open(results_file, 'a')as f:
            extracted = re.findall(regex_for_domain_names, domain_matches)
            domain_names = str(extracted)
            domain_names.replace(']', '').replace('[', '').split(',')
            f.write(domain_names + '\n')
    
    print(f'[!] Complete. File written to: {results_file}')

       
def scan_all_occurrences(query_str: str) -> str:
    """
    Return all instances of the queried search term 
    Args: query_str 
    Returns: 
    str -> All instances where the query appears in the file
    """
    
    path = Path.cwd() / f'{query_str}_matches.txt'
    list_of_domains = process_domain_file()

    for search_all in list_of_domains:

        if query_str in search_all:
           
            print(f'[*] {search_all}')

            with open(path, 'a')as f:
                f.write(search_all+'\n')

# ADD CHECK IF NONE, DONT PRINT
    print()
    print(f'[+] Results written to: {path}\n')
    
       
def main():

    banner = """
  __   __                    __   __   __  ___ ___  ___  __  
 |  \ /  \ |\/|  /\  | |\ | /__` |__) /  \  |   |  |__  |__) 
 |__/ \__/ |  | /~~\ | | \| .__/ |    \__/  |   |  |___ |  \                                                                           
--------------------------------------------------------------------------
"""

    parser = argparse.ArgumentParser(description=f"{banner}\nBy: {AUTHOR}\tLast_Seen: {LAST_SEEN}\n\nDescription: {DESCRIPTION}".format(banner, AUTHOR, LAST_SEEN, DESCRIPTION), formatter_class=argparse.RawTextHelpFormatter)
    
    parser.add_argument(
        "-r",
        "--rfuzz",
        help="Scan a list of keywords for similarity using RapidFuzz.")

    parser.add_argument(
        "-a",
        "--all",
        help="Generic scan for all occurrences of a single keyword.")

    args = parser.parse_args()

    if args.rfuzz:
        print(banner)
        print()
        rapidfuzz_multi_query(args.rfuzz)
        
    elif args.all:
        print(banner + '\n')
        print('[!] Returning results if found, exits if none...\n')
        scan_all_occurrences(args.all)
        
    else:
        print("[!] No argument was provided. Try again...\n")
        parser.print_help()


if __name__ == "__main__":
    main()
