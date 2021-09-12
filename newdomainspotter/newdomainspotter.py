import argparse
import base64
from io import BytesIO
from datetime import datetime, timedelta
from rapidfuzz import process
import requests
from rich import print
from rich.console import Console
from zipfile import ZipFile


console = Console()

WHOISDS_URL = "https://whoisds.com//whois-database/newly-registered-domains/"


def set_date_in_url() -> str:
    yesterday = datetime.now() - timedelta(days=1)
    format_date = datetime.strftime(yesterday, "%Y-%m-%d")
    url_add_ext = format_date + ".zip"
    finished_url_date = base64.b64encode(
        url_add_ext.encode("utf-8")).decode("utf-8")
    return finished_url_date


def get_new_domains():
    url_with_date = set_date_in_url()
    new_domain_list = []
    try:
        whois_new_domains_url = requests.get(
            WHOISDS_URL + url_with_date + "/nrd")
        whois_new_domains_url.raise_for_status()
        #print(whois_new_domains_url.status_code)
        try:
            with ZipFile(BytesIO(whois_new_domains_url.content)) as datafile:
                
                for x in datafile.infolist():
                    with datafile.open(x) as data:
                        for line in data:
                          
                            new_domains = line.decode("ascii")
                            new_domain_list.append(str(new_domains).rstrip("\r\n"))

        except ZipFile.BadZipFile:
            print("[red] error opening zip [/red]")

    except requests.RequestException:
        print("[red]An error occured [/red]")

    return new_domain_list


def rapidfuzz_new_domains(dom2match) -> tuple:
    domains_to_search = get_new_domains()
    domain_sim_ratio = process.extract(dom2match, domains_to_search)
    
    for ratio in zip(domain_sim_ratio):
        similarity_result = ", ".join(map(str, ratio))
        console.print(similarity_result, highlight=False)


def simulate_control_f_search(wildcard) -> str:
    domains = get_new_domains()
    
    for all_domains in domains:
        if wildcard in all_domains:
            console.print(all_domains, highlight=False)


def main():

    banner = """
      ___       __   __                     __   __   __  ___ ___  ___  __  
|\ | |__  |  | |  \ /  \ |\/|  /\  | |\ | /__` |__) /  \  |   |  |__  |__) 
| \| |___ |/\| |__/ \__/ |  | /~~\ | | \| .__/ |    \__/  |   |  |___ |  \ 
                                                                            
----------------------------------------------------------------
Download a list of newly registered domains and spot suspicious domains
which may be indicative of phishing, or other malicious uses. 

Examples:
\t python newdomainspotter.py -r 'google'
\t python newdomainspotter.py -a 'microsoft'

"""

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=banner,
    )
    parser.add_argument("-r", "--rfuzz", help="""Identify similar domains with a 
        single keyword using RapidFuzz""")
    parser.add_argument("-a", "--all",
                        help="Generic single keyword search, similar to Ctrl+F", 
                        action="store_true")

    args = parser.parse_args()

    if args.rfuzz:
        rapidfuzz_new_domains(args.rfuzz)
    elif args.all:
        simulate_control_f_search(args.all)


if __name__ == "__main__":
    main()
    
