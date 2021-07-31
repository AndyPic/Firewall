import json, os, ipaddress, random, yaml
from timeit import default_timer as timer

""" Simple script to generate blocklists """

# This is the network to be considered 'local' from the scenario file
# ie. the network that will be protected by the firewall
LOCAL_HOST_NAME = "n1"
# The name of the scenario file to generate a blocklist for
SCENARIO_NAME = "firewall.yaml"

# The ratio of networks to block entirely
NETWORK_BLOCK_RATIO = 0.5
# The ratio of IPs from the remaining networks to block
IP_BLOCK_RATIO = 0.01

# Get the scenario file, if it doesnt exist SCENARIO = None
SCENARIO = (
    os.path.dirname(__file__).replace("src\.blocklist", "scenarios/") + SCENARIO_NAME
)
if not os.path.isfile(SCENARIO):
    exit("Invalid scenario file path {}".format(SCENARIO))

# Define blocklist dictionary
blocklists_dict = {"mac": [], "ipv4_mask": [], "ipv4": {}}

# script_run_mininet.py has been edited to statically assign mac adresses in the same way
if SCENARIO != None:
    with open(SCENARIO, "r") as scenario_file:
        # If the scenario file exists, read in the yaml info and get the hosts
        data = scenario_file.read()
        hosts = yaml.safe_load(data)["root"]["topology"]["hosts"]

        # Get index of local host
        for host in hosts:
            if host["name"] == LOCAL_HOST_NAME:
                local_host = host
                local_ip = ipaddress.ip_network(host["ip"])

        # New list without local host
        external_hosts = hosts.copy()
        external_hosts.remove(local_host)

        # Get the hosts to be blocked
        num_net_block = int(len(external_hosts) * float(NETWORK_BLOCK_RATIO))
        net_block = random.sample(external_hosts, num_net_block)
        #net_block = [external_hosts[1], external_hosts[3]] # Manually set hosts for speed testing

        # Start mac address from 0
        mac = "0x000000000000"
        # Iterate over all the hosts
        for host in hosts:
            # Increment the mac address for each host
            mac = "{:012X}".format(int(mac, 16) + 1)
            mac_address = ":".join(mac[i] + mac[i + 1] for i in range(0, len(mac), 2))
            if host in net_block:
                # Add mac addresses to mac blocklist
                blocklists_dict["mac"].append(mac_address)
                # Add masked IP addresses to ipv4_mask blocklist
                blocklists_dict["ipv4_mask"].append(host["ip"])
            elif host != local_host:
                # If not blocking whole network, block some IPs from that network (exclude local network)
                for ip in ipaddress.IPv4Network(host["ip"]):
                    if random.random() <= IP_BLOCK_RATIO:
                        blocklists_dict["ipv4"][format(ip)] = int(ip) # Hashable dict
                        #blocklists_dict["ipv4"].append(int(ip)) # List of 32-bit ints

# Quick efficiency test
start_time = timer()
if "00.00.00.00" in blocklists_dict["ipv4"]:
    pass
elapsed = timer() - start_time
print(elapsed)

# Check loaded traffic schedule for this scenario & calculate expected packets (packet ratio)
# Probably only works for single schedule named 'default' & a single target host
schedule_path = os.path.dirname(__file__).replace(
    "local\\apps\\src\\.blocklist", "cwd\\firewall\\schedule_default.json"
)
schedule_json = open(schedule_path)
schedule = json.load(schedule_json)

# Get expected and total packets
packets = 0
expected_packets = 0
count = 0
for event in schedule["schedule"]:
    skip = False
    packets += event["packets"]

    # Check if dst is local_network
    if event["dst_host"] == LOCAL_HOST_NAME:
        count += 1

        if event["src_ip"] in blocklists_dict["ipv4"]:
            continue
        
        # Iterate over the ipv4_mask blocklist
        for i in blocklists_dict["ipv4_mask"]:
            # Store the ipv4 networks from blocklist in an ip_network obj
            ipv4_network = ipaddress.ip_network(i)
            # Check if src in network
            if ipaddress.ip_address(event["src_ip"]) in ipv4_network:
                skip = True
                break
        
        if skip:
            continue

        expected_packets += event["packets"]

# Print expected to console, incase yaml doesn't update, can do manually
print(expected_packets)

# Calculate expected_ratio
expected_ratio = expected_packets / packets

# Load in scenario yaml and update packet_ratio
with open(SCENARIO, ) as scenario_file:
    data = yaml.safe_load(scenario_file)
for elem in data["root"]["networks"]:
    if elem["name"] == LOCAL_HOST_NAME:
         elem["packet_ratio"] = str(expected_ratio)
         break  # no need to iterate further

# Overwrite with new yaml file
# NOTE: Does not preserve comments / structure may change slightly
# seems to be an ongoing issue with the yaml lib!
with open(SCENARIO, "w") as scenario_file:
    yaml.dump(data, scenario_file, default_flow_style=False)

# cwd to this location
os.chdir(os.path.dirname(__file__))

# Write to json file
json_string = json.dumps(blocklists_dict)
json_file = open("blocklist.json", "w")
json_file.write(json_string)
json_file.close()
