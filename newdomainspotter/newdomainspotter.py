import argparse
import base64
from io import BytesIO
from datetime import datetime, timedelta
from rapidfuzz import process
import requests
from rich import print
from rich.console import Console
from typing import List, Tuple
from zipfile import ZipFile


console = Console()

WHOISDS_URL = "https://whoisds.com//whois-database/newly-registered-domains/"


def set_date_in_url() -> str:
    """Set date to yesterday's date in
    
    Args: None  
    
    Returns: 
        str -> Yesterday's date Base64 encoded with additional information for URL
    """
    yesterday = datetime.now() - timedelta(days=2)
    format_date = datetime.strftime(yesterday, "%Y-%m-%d")
    url_add_ext = format_date + ".zip"
    finished_url_date = base64.b64encode(url_add_ext.encode("utf-8")).decode("utf-8")
    return finished_url_date


def get_new_domains() -> requests.Response:
    """Fetch content from WHOISDS website for new domains file 
    
    Args: None 
    
    Returns: 
        requests.Response -> Content of server response
        (zip file of newly registered domains)
    """
    url_with_date = set_date_in_url()

    try:
        whois_new_domains_url = requests.get(WHOISDS_URL + url_with_date + "/nrd")
        whois_new_domains_url.raise_for_status()

    except requests.RequestException:
        print("[red]An error occured [/red]")

    return whois_new_domains_url.content


def open_process_domainlist_zip_file() -> List[str]:
    """Open and read returned zip file from request 
    
    Args: None 
    
    Returns: 
        List[str] -> The zip file is read and returns each newly 
        identified domain as a list of strings.
    """
    testme = get_new_domains()
    new_domain_list = []

    try:
        with ZipFile(BytesIO(testme)) as datafile:

            for x in datafile.infolist():
                with datafile.open(x) as data:
                    for line in data:

                        new_domains = line.decode("ascii")
                        new_domain_list.append(str(new_domains).rstrip("\r\n"))

    except Exception:
        print(
            """[red] Error opening zip file. You may need to change the 'days' range.[/red]"""
        )

    return new_domain_list


def rapidfuzz_search_for_domains(domainMatch: str) -> List[Tuple]:
    """Return RapidFuzz string match of search query 
    
    Args: domainMatch 
    
    Returns: 
    List[Tuple] -> Best matches based on similarity
     """
    domains_to_search = open_process_domainlist_zip_file()
    domain_sim_ratio = process.extract(domainMatch, domains_to_search)

    for ratio in zip(domain_sim_ratio):
        similarity_result = ", ".join(map(str, ratio))
        console.print(similarity_result, highlight=False)


def control_f_type_search(wildcard_search: str) -> str:
    """Return all instances of the queried search term 
    
    Args: wildcard_search 
    
    Returns: 
    str -> All instances where the query appears in the file
    """
    list_of_domains = open_process_domainlist_zip_file()

    for search_all_instances in list_of_domains:
        if wildcard_search in search_all_instances:
            console.print(search_all_instances, highlight=False)


def main():

    banner = """
      ___       __   __                     __   __   __  ___ ___  ___  __  
|\ | |__  |  | |  \ /  \ |\/|  /\  | |\ | /__` |__) /  \  |   |  |__  |__) 
| \| |___ |/\| |__/ \__/ |  | /~~\ | | \| .__/ |    \__/  |   |  |___ |  \ 
                                                                            
----------------------------------------------------------------
This program downloads and unzips the latest WHOISDS newly registered domains
list. Searches can be based on similarity matching with RapidFuzz, or a 
Ctrl+F type search returning all instances of the query.

Examples:
\t python newdomainspotter.py -r 'google'
\t python newdomainspotter.py -a 'microsoft'

"""

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=banner,
    )
    parser.add_argument(
        "-r",
        "--rfuzz",
        help="""Identify similar domains with a 
        single keyword using RapidFuzz""",
    )
    parser.add_argument(
        "-a",
        "--all",
        help="Generic single keyword search, similar to Ctrl+F",
        action="store_true",
    )

    args = parser.parse_args()

    if args.rfuzz:
        print(banner)
        rapidfuzz_search_for_domains(args.rfuzz)
    elif args.all:
        print(banner)
        control_f_type_search(args.all)
    else:
        print(banner)


if __name__ == "__main__":
    main()
