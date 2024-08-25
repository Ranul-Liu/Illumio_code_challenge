import csv
import argparse
import os

PROTOCOL_NUMBERS = {
  "0": "HOPOPT",
  "1": "ICMP",
  "2": "IGMP",
  "3": "GGP",
  "4": "IPv4",
  "5": "ST",
  "6": "TCP",
  "7": "CBT",
  "8": "EGP",
  "9": "IGP",
  "10": "BBN-RCC-MON",
  "11": "NVP-II",
  "12": "PUP",
  "13": "ARGUS (deprecated)",
  "14": "EMCON",
  "15": "XNET",
  "16": "CHAOS",
  "17": "UDP",
  "18": "MUX",
  "19": "DCN-MEAS",
  "20": "HMP",
  "21": "PRM",
  "22": "XNS-IDP",
  "23": "TRUNK-1",
  "24": "TRUNK-2",
  "25": "LEAF-1",
  "26": "LEAF-2",
  "27": "RDP",
  "28": "IRTP",
  "29": "ISO-TP4",
  "30": "NETBLT",
  "31": "MFE-NSP",
  "32": "MERIT-INP",
  "33": "DCCP",
  "34": "3PC",
  "35": "IDPR",
  "36": "XTP",
  "37": "DDP",
  "38": "IDPR-CMTP",
  "39": "TP++",
  "40": "IL",
  "41": "IPv6",
  "42": "SDRP",
  "43": "IPv6-Route",
  "44": "IPv6-Frag",
  "45": "IDRP",
  "46": "RSVP",
  "47": "GRE",
  "48": "DSR",
  "49": "BNA",
  "50": "ESP",
  "51": "AH",
  "52": "I-NLSP",
  "53": "SWIPE (deprecated)",
  "54": "NARP",
  "55": "Min-IPv4",
  "56": "TLSP",
  "57": "SKIP",
  "58": "IPv6-ICMP",
  "59": "IPv6-NoNxt",
  "60": "IPv6-Opts",
  "61": "any host internal protocol",
  "62": "CFTP",
  "63": "any local network",
  "64": "SAT-EXPAK",
  "65": "KRYPTOLAN",
  "66": "RVD",
  "67": "IPPC",
  "68": "any distributed file system",
  "69": "SAT-MON",
  "70": "VISA",
  "71": "IPCV",
  "72": "CPNX",
  "73": "CPHB",
  "74": "WSN",
  "75": "PVP",
  "76": "BR-SAT-MON",
  "77": "SUN-ND",
  "78": "WB-MON",
  "79": "WB-EXPAK",
  "80": "ISO-IP",
  "81": "VMTP",
  "82": "SECURE-VMTP",
  "83": "VINES",
  "84": "IPTM",
  "85": "NSFNET-IGP",
  "86": "DGP",
  "87": "TCF",
  "88": "EIGRP",
  "89": "OSPFIGP",
  "90": "Sprite-RPC",
  "91": "LARP",
  "92": "MTP",
  "93": "AX.25",
  "94": "IPIP",
  "95": "MICP (deprecated)",
  "96": "SCC-SP",
  "97": "ETHERIP",
  "98": "ENCAP",
  "99": "any private encryption scheme",
  "100": "GMTP",
  "101": "IFMP",
  "102": "PNNI",
  "103": "PIM",
  "104": "ARIS",
  "105": "SCPS",
  "106": "QNX",
  "107": "A/N",
  "108": "IPComp",
  "109": "SNP",
  "110": "Compaq-Peer",
  "111": "IPX-in-IP",
  "112": "VRRP",
  "113": "PGM",
  "114": "any 0-hop protocol",
  "115": "L2TP",
  "116": "DDX",
  "117": "IATP",
  "118": "STP",
  "119": "SRP",
  "120": "UTI",
  "121": "SMP",
  "122": "SM (deprecated)",
  "123": "PTP",
  "124": "ISIS over IPv4",
  "125": "FIRE",
  "126": "CRTP",
  "127": "CRUDP",
  "128": "SSCOPMCE",
  "129": "IPLT",
  "130": "SPS",
  "131": "PIPE",
  "132": "SCTP",
  "133": "FC",
  "134": "RSVP-E2E-IGNORE",
  "135": "Mobility Header",
  "136": "UDPLite",
  "137": "MPLS-in-IP",
  "138": "manet",
  "139": "HIP",
  "140": "Shim6",
  "141": "WESP",
  "142": "ROHC",
  "143": "Ethernet",
  "144": "AGGFRAG",
  "145": "NSH",
  "253": "Use for experimentation and testing",
  "254": "Use for experimentation and testing",
  "255": "Reserved"
}

# Read the loolup table file
def read_lookup_table(lookup_file_path):
    try:
        lookup_table = {}
        with open(lookup_file_path, "r") as f:
            csvreader = csv.DictReader(f)
            for row in csvreader:
                dstport = row["dstport"]
                protocol = row["protocol"].lower()
                tag = row["tag"]
                if (dstport, protocol) not in lookup_table:
                    lookup_table[(dstport, protocol)] = tag
                else:
                    raise Exception("The pair {0} appears more than once in {1}, please check.".format((dstport, protocol), lookup_file_path))
        return lookup_table
    except Exception as e:
        print("An error, {0}, occured while trying to process the lookup table.".format(e))
        return
    
# Read the log file, it assumes that it is always valid
def read_log_file(log_file_path):
    try:
        logs = {}
        with open(log_file_path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    segments = line.split()
                    if segments[0] != "2":
                        raise Exception("The log file {0} is not in version 2, please check.".format(log_file_path))
                    dstport = segments[6]
                    protocol_number = segments[7]
                    protocol = PROTOCOL_NUMBERS.get(protocol_number, "Unassigned").lower()
                    logs[(dstport, protocol)] = logs.get((dstport, protocol), 0) + 1
        return logs
    except Exception as e:
        print("An error, {0}, occured while trying to process the log.".format(e))
        return

# Check if the given output file already exists.
def check_output_file(output_path):
    return os.path.exists(output_path)

# Write the result to the output file
def write_output_file(output_path, tag_counts, logs):
    try:
        with open(output_path, 'w') as file:
            file.write("Tag Counts:\n")
            file.write("Tag,Count\n")
            for key in tag_counts:
                file.write("{0},{1}\n".format(key, tag_counts[key]))
            file.write("\nPort/Protocol Combination Counts:\n")
            file.write("Port,Protocol,Count\n")
            for key in logs:
                file.write("{0},{1},{2}\n".format(key[0], key[1], logs[key]))
    except Exception as e:
        print("An error, {0}, occured while trying to write result output.".format(e))
        return

# Return the dict for each tag's count
def count_tags(lookup_table, logs):
    tag_counts = {}
    for key in logs:
        tag = lookup_table.get(key, "Untagged")
        tag_counts[tag] = logs[key] + tag_counts.get(tag, 0)
    return tag_counts

def main(log_file_path, lookup_file_path, output_path):
    if check_output_file(output_path):
        print("The given output file {0} already exists. It will not be overwritten. Program ends.".format(output_path))
        return
    lookup_table = read_lookup_table(lookup_file_path)
    if not lookup_table:
        print("The lookup file {0} is empty or an exception has occured.".format(lookup_file_path))
        return
    logs = read_log_file(log_file_path)
    if not logs:
        print("The log file {0} is empty or an exception has occured.".format(log_file_path))
        return
    tag_counts = count_tags(lookup_table, logs)
    write_output_file(output_path, tag_counts, logs)
    print("Successfully write output to {0}".format(output_path))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="This program accepts ")

    parser.add_argument("log_file_path", help="The path to the log file. It should be a plain text AWS version 2 flow log file.")
    parser.add_argument("lookup_file_path", help="The path to the lookup table file. It should be a csv file with header dstport, protocol, tag.")
    parser.add_argument("--output_path", help="The path and name of the output file. If it exists, program will not run. By default it is counts.txt", default="counts.txt")

    args = parser.parse_args()

    main(args.log_file_path, args.lookup_file_path, args.output_path)