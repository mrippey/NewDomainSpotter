AUTHOR = "Michael Rippey, Twitter: @nahamike01"
LAST_SEEN = "2022 01 09"
DESCRIPTION = """Download/search for suspicious domains from the WHOISDS database. 

usage: python3 newdomainspotter.py -rfuzz <<str(keyword)>>  || -a <<str(keyword)>>"""

import argparse
import base64
import json
import os
from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path
from time import sleep
from typing import List, Tuple
from zipfile import ZipFile

import requests
from dotenv import load_dotenv
from rapidfuzz import process
from requests.auth import HTTPBasicAuth

load_dotenv()


WHOISDS_URL = "https://whoisds.com//whois-database/newly-registered-domains/"


def format_date_url() -> str:
    """
    Set date to yesterday"s date in
    Args: None  
    Returns: 
    str -> Yesterday"s date Base64 encoded with additional information for URL
    """
    yesterday = datetime.now() - timedelta(days=2)
    format_date = datetime.strftime(yesterday, "%Y-%m-%d")
    url_add_ext = format_date + ".zip"
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
        headers = {"User-Agent": "NewDomainSpotter v0.2 (github: @mrippey"}
        whoisds_new_domains = requests.get(WHOISDS_URL + add_date_url + "/nrd", headers=headers)
        whoisds_new_domains.raise_for_status()

    except requests.RequestException as e:
        print("[!] Requests Module Exception: {e}")

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
        with ZipFile(BytesIO(domain_file)) as data:

            for info in data.infolist():
                with data.open(info) as lines:
                    for line in lines:

                        file = line.decode("ascii")
                        domains.append(str(file).rstrip("\r\n"))

    except ZipFile.BadZipFile as e:
        print(f"[!] Exception: {e}")

    return domains


def str_match_rapidfuzz(query_str: str) -> List[Tuple]:
    """
    Return RapidFuzz string match of search query 
    Args: query_str 
    Returns: 
    List[Tuple] -> Best matches based on similarity
    """
    domains_to_search = process_domain_file()
    domain_sim_ratio = process.extract(query_str, domains_to_search, limit=10)

    for word_sim in zip(domain_sim_ratio):
        similarity_result = ", ".join(map(str, word_sim))
        cleaned_result = str(similarity_result)[1:-1].replace("'", '')
        print(cleaned_result)


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


    print(f'[+] Results written to: {path}\n')
    #TODO Integrate IBM XForce URL Report
    print('[*] IBM XForce URL Report\n')
    xfe_key = os.getenv('XFE_KEY')
    xfe_pass = os.getenv('XFE_PASS')
    try:
        url = 'https://api.xforce.ibmcloud.com/url/'
        for item in search_all:
            response = requests.get(url+item, auth=HTTPBasicAuth(xfe_key, xfe_pass))
            sleep(10)
        
        responsejson = json.loads(response.text)
        print(responsejson)

    except Exception as e:
        print(f'[!] {e}')

       


def main():

    banner = """
  __   __                    __   __   __  ___ ___  ___  __  
 |  \ /  \ |\/|  /\  | |\ | /__` |__) /  \  |   |  |__  |__) 
 |__/ \__/ |  | /~~\ | | \| .__/ |    \__/  |   |  |___ |  \                                                                           
--------------------------------------------------------------------------
"""

    parser = argparse.ArgumentParser(description="{}\nBy: {}\tLast_Seen: {}\n\nDescription: {}".format(banner, AUTHOR, LAST_SEEN, DESCRIPTION), 
    formatter_class=argparse.RawTextHelpFormatter)
    
    parser.add_argument(
        "-r",
        "--rfuzz",
        help="Identify domains of a certain similarity using RapidFuzz")

    parser.add_argument(
        "-a",
        "--all",
        help="Generic scan for all occurrences of provided keyword. Accepts keyword and path to file")

    args = parser.parse_args()

    if args.rfuzz:
        print(banner)
        print()
        print("[!] Returning results if found, exits if not...\n")
        str_match_rapidfuzz(args.rfuzz)
    elif args.all:
        print(banner + '\n')
        print('[!] Returning results if found, exits if none...\n')
        scan_all_occurrences(args.all)
        
    else:
        print(['[!] Didn\t understand that. Try again...\n'])
        print(parser.print_help)


if __name__ == "__main__":
    main()
