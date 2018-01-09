# --------------------------------------------------------------------------------------------
# Copyright (c) 2017 Stefan Grimminck. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

# !/usr/bin/env python3

import argparse
import csv
import json
import re
import requests
import sys
import time


def getdata(body, outfile):
    """This methode sends a request to the API with a request for scanning of the in 'body' defined domains.

    Args:
        body (string): Json object with domains to be scanned.
        outfile (string): Output file."""

    headers = {'Authorization': 'Basic ENCODED CREDENTIALS'}
    url = "API URL" + scantype + "/"
    r = requests.post(url, data=body, headers=headers)
    responsebody = r.content.decode()
    print(responsebody)

    if "\"success\": true" in responsebody:
        response_url = re.search("(?P<url>https?://[^\s]+[/])", responsebody).group("url")
        pollresponse(response_url, 0, outfile)


def parsejson(responsebody, outfile):
    """Rewrites the received json file to seperate json objects sothat logstash can parse the data.
    Args:
        responsebody (string): string containing the json data received by the  API
        outfile (string): Output file."""

    newoutput = ''.join(re.findall(r'"domains": \[(.*?)\], "finished-date"', responsebody))
    parsedoutput = newoutput.replace('}, {"status', '}\n{"status')

    json_objects = parsedoutput.splitlines()

    domains = []
    institutions = []
    sectors = []

    with open(infile.name) as csvfile:
        readCSV = csv.reader(csvfile, delimiter=';')

        # Read trough input file and write variables into lists.
        for row in readCSV:
            domain = row[0]
            sector = row[1]
            institution = row[2]

            domains.append(domain)
            institutions.append(institution)
            sectors.append(sector)

    if scantype == "web":
        for item in json_objects:
            jsonoutput = json.loads(item)
            jsonoutput['ipv6'] = jsonoutput["categories"][0]["passed"]
            jsonoutput['dnssec'] = jsonoutput["categories"][1]["passed"]
            jsonoutput['tls'] = jsonoutput["categories"][2]["passed"]

            jsonoutput['tls_available'] = jsonoutput["views"][0]["result"]
            jsonoutput['tls_ncsc_web'] = jsonoutput["views"][1]["result"]

            received_domain = jsonoutput['domain']

            # check on witch index the received domain matches with a domain in the input files.
            domain_index = domains.index(received_domain)

            # locate sector based on index of domain
            jsonoutput['sector'] = sectors[domain_index]
            # locate institution on index of domain
            jsonoutput['institution'] = institutions[domain_index]

            del jsonoutput["views"]
            del jsonoutput["categories"]

            with open(outfile, 'a') as f:
                json.dump(jsonoutput, f)
                f.write('\n')
    else:
        for item in json_objects:
            jsonoutput = json.loads(item)
            jsonoutput['ipv6'] = jsonoutput["categories"][0]["passed"]
            jsonoutput['dnssec'] = jsonoutput["categories"][1]["passed"]
            jsonoutput['auth'] = jsonoutput["categories"][2]["passed"]
            jsonoutput['tls'] = jsonoutput["categories"][3]["passed"]

            jsonoutput['dkim'] = jsonoutput["views"][0]["result"]
            jsonoutput['dmarc'] = jsonoutput["views"][1]["result"]
            jsonoutput['spf'] = jsonoutput["views"][2]["result"]
            jsonoutput['tls_available'] = jsonoutput["views"][3]["result"]

            received_domain = jsonoutput['domain']

            # check on witch index the received domain matches with a domain in the input files.
            domain_index = domains.index(received_domain)

            # locate sector based on index of domain
            jsonoutput['sector'] = sectors[domain_index]
            # locate institution on index of domain
            jsonoutput['institution'] = institutions[domain_index]

            del jsonoutput["views"]
            del jsonoutput["categories"]

            with open(outfile, 'a') as f:
                json.dump(jsonoutput, f)
                f.write('\n')


def pollresponse(URL, counter, outfile):
    """Methode that send get requests to the  API to check if the scan has completed.
    Note:
        This method is recursive. If the scan isn't complete it will sleep for 5 seconds and calls itself again.
    Args:
        URL (string): URL where the results will be requested from
        counter(int): Serves as a time-out counter. timeout is set as script argument.
        outfile(string): Output file."""

    headers = {'Authorization': 'Basic ENCODED CREDENTIALS'}
    r = requests.get(URL, headers=headers)
    responsebody = r.content.decode()

    if "\"success\": true" in responsebody:
        return parsejson(responsebody, outfile)
    else:
        time.sleep(5)
        if counter / 5 >= timeout:
            sys.exit("Polling time has expired, no results were returned")
        else:
            counter += 1
            print(responsebody)
            print('.' * counter)
            pollresponse(URL, counter, outfile)


def messagebuilder(infile, testname):
    """  
    Note:
        This method is only called for IPv4 addresses.
    Args:
        ranges (Dictionary): A dictionary containing a dictionary containing an array.
            This "Tree" contains IPv4 addresses that should be saved
        block1 (int): The first block of a IPv4 address.
        block2 (int): The second block of a IPv4 address.
        block3 (int): The third block of a IPv4 address.
        block4 (int): The fourth block of a IPv4 address.
     Returns:
         True if it should be saved, False otherwise."""

    with open(infile) as csvfile:
        r = csv.reader(csvfile, delimiter=';')
        jsonmessage = '{"name":"' + testname + '","domains":['
        for row in r:
            jsonmessage = jsonmessage + "\"" + row[0] + "\", "

        jsonmessage = jsonmessage[:-2]
        jsonmessage = jsonmessage + ']}'

    return (jsonmessage)


def main(arguments):
    global scantype
    global timeout
    global infile

    # Specify required arguments
    """
    Input csv files should be structured like this:
    |domainname|institution|sector|
    """  
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("infile", help="Input file", type=argparse.FileType("r"))
    parser.add_argument("outfile", help="Output file", type=argparse.FileType("w"))
    parser.add_argument("testtype", choices=['mail', 'web'], default='web')
    parser.add_argument("testname", help="Name of test")
    parser.add_argument("timeout", help="maximum time for the scan to complete in seconds.", type=int, default=86400)

    # Convert args to usable variables
    args = parser.parse_args(arguments)
    infile = args.infile
    outfile = args.outfile
    testname = args.testname
    timeout = args.timeout
    scantype = args.testtype

    jsondata = messagebuilder(infile.name, testname)
    getdata(jsondata, outfile.name)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
