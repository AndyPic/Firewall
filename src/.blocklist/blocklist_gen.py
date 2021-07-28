import json, os, ipaddress, random

""" Simple script to generate blocklists """

# TODO - get ip addresses from scenario file (static code bad!)

os.chdir(os.path.dirname(__file__))

blocklists_dict = {"mac": [], "ipv4": [], "ipv4_mask": []}

# Add mac addresses for n2 and n4 to mac blocklist
blocklists_dict["mac"].append("00:00:00:00:00:02")
blocklists_dict["mac"].append("00:00:00:00:00:04")

# Generate some random IPs from mask of n3 & n5
for ip in ipaddress.IPv4Network('33.0.0.0/16'):
    #5% chance to add ip to list
    if random.random() >= 0.95:
        blocklists_dict["ipv4"].append(str(ip))

for ip in ipaddress.IPv4Network('55.0.0.0/24'):
    #20% chance to add ip to list
    if random.random() >= 0.8:
        blocklists_dict["ipv4"].append(str(ip))

# Add masked IP addresses for n2 and n4 to ipv4_mask blocklist
blocklists_dict["ipv4_mask"].append("22.0.0.0/8")
blocklists_dict["ipv4_mask"].append("44.0.0.0/8")

jsonString = json.dumps(blocklists_dict)
jsonFile = open("blocklist.json", "w")
jsonFile.write(jsonString)
jsonFile.close()