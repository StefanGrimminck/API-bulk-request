def parsejson(responsebody, outfile):
    newoutput = ''.join(re.findall(r'"domains": \[(.*?)\], "finished-date"', responsebody))
    parsedoutput = newoutput.replace('}, {"status', '}\n{"status')

    list = parsedoutput.splitlines()

    for item in list:
        jsonoutput = json.loads(item)
        jsonoutput['ipv6'] = jsonoutput["categories"][0]["passed"]
        jsonoutput['dnssec'] = jsonoutput["categories"][1]["passed"]
        jsonoutput['tls'] = jsonoutput["categories"][2]["passed"]
        jsonoutput['tls_available'] = jsonoutput["views"][0]["result"]
        jsonoutput['tls_ncsc_web'] = jsonoutput["views"][0]["result"]

        del jsonoutput["views"]
        del jsonoutput["categories"]

        with open(outfile.name, 'a') as f:
            json.dump(jsonoutput, f)
            f.write('\n')



def main(arguments):
    # Specify required arguments
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("infile", help="Input file", type=argparse.FileType("r"))
    parser.add_argument("outfile", help="Output file", type=argparse.FileType("w"))

    # Convert args to usable variables
    args = parser.parse_args(arguments)
    infile = args.infile
    outfile = args.outfile

    with open(infile.name, 'r') as content_file:
        jsondata = content_file.read()
        parsejson(jsondata, outfile)



    #inputlist = ""
    #getdata(inputlist)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
