AUTHOR = "Michael Rippey, Twitter: @nahamike01"
LAST_SEEN = "2021 12 30"
DESCRIPTION = """Download/search for suspicious domains from the WHOISDS database. 

usage: python3 newdomainspotter.py -rfuzz <<str(keyword)>>  || -a <<str(keyword)>>"""

import argparse
import base64
from io import BytesIO
from datetime import datetime, timedelta
from rapidfuzz import process
import requests
from typing import List, Tuple
from zipfile import ZipFile
from pathlib import Path


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
        print(cleaned_result, highlight=False)


def scan_all_occurrences(query_str: str) -> str:
    """
    Return all instances of the queried search term 
    Args: query_str 
    Returns: 
    str -> All instances where the query appears in the file
    """
    path = Path.cwd() / f'{query_str}_matches.txt'
    list_of_domains = process_domain_file()
    
    for search_all_instances in list_of_domains:

        if query_str not in search_all_instances:
            print(f'[!] Sorry, there were no matches for {query_str} among the newly registered domains.\n')
            exit()
        elif query_str in search_all_instances:
            print(search_all_instances, highlight=False)
            
            with open(path, 'a')as f:
                f.write(search_all_instances+'\n')

        print(f'[+] Results written to: {path}\n')


def main():

    banner = """
      ___       __   __                    __   __   __  ___ ___  ___  __  
|\ | |__  |  | |  \ /  \ |\/|  /\  | |\ | /__` |__) /  \  |   |  |__  |__) 
| \| |___ |/\| |__/ \__/ |  | /~~\ | | \| .__/ |    \__/  |   |  |___ |  \                                                                           
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
        print("Returning results...\n")
        str_match_rapidfuzz(args.rfuzz)
    elif args.all:
        print(banner + '\n')
        print('Returning results...\n')
        scan_all_occurrences(args.all)
    else:
        print(['[!] Didn\t understand that. Try again...\n'])
        print(parser.print_help)


if __name__ == "__main__":
    main()
