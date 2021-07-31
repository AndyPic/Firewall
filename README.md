## README ##

**Installation / setup:**

(Ensure sdn-cockpit is not running before starting)

Recommend making a copy of your files before over-writing with mine.

1. Replace script_run_mininet.py with the one provided here
	(Minor change to have mac addresses assigned statically from 00:00:00:00:01 up, rather than randomly)

2. Replace proxy.py with the one provided here
	(Fixes an error in the original file so packet_ratio's work correctly)

3. **OPTIONAL** Replace run.sh with the one provided here to load firewall as default instead of demo.

4. Merge scenarios, src and tasks folder with you local folders within sdn-cockpit

5. Launch sdn-cockpit as normal.

6. If you didn't replace run.sh (step 3) load the firewall.py application, and firewall.yaml task & scenario

Should be good to go!

**The Topology**

<img src="https://gitlab2.eeecs.qub.ac.uk/40315028/csc7078-project-andrewpickard/raw/master/imgs/Topology.png" />

Fig 1. Visual representation of the topology described below

This is a relatively simple, 5 network connected via a single switch topology.
**n1** is used to represent the 'local network' ie. the network we wish the firewall application to defend,
- mac address: 00:00:00:00:00:01
- ip network: 11.0.0.0/16 (mask 11.0.255.255)

**n2 - n5** are used to represent 'external networks' ie. networks that will interact with the local network via the switch
- mac address': 00:00:00:00:00:02 - 05
- n2 ip network: 22.0.0.0/8 (mask 22.255.255.255)
- n3 ip network: 33.0.0.0/16 (mask 33.0.255.255)
- n4 ip network: 44.0.0.0/8 (mask 44.255.255.255)
- n5 ip network: 55.0.0.0/24 (mask 55.0.0.255)

**Overview of the application**

This controller will perform the following tasks:
- Drop all packets that are not either destined, or sourced from the 'local host' (n1 in the topology, by default)
- Read in the blocklist (.blocklists/blocklist.json) from file
- Protect the local host by preventing in-bound connection from any hosts defined within the blocklist
	- MAC addresses
	- Individual IP addresses
	- Enitre IP networks
- On switch connection, a single default flow rule is set to forward all trafic to the controller.
- If an inbound packet is from a host in the blocklist, the packet will be dropped and a flow rule installed to drop subsequent packets from that host, to the local host
	- With no hard-timeout and an idle time-out of 30 minutes -> to reduce load on the controller, but allow rules to drop off eventually incase blocklist changes
- If an inbound packet is not from a blocked host, the packet will be forwarded to the relevant local host ip and a flow rule install to forward subsequent packets.
- The controller will also provide various useful information via print() statements.

The blocklist data was generated using the 'blocklist_gen.py' application that I wrote (in src/.blocklist folder).

The blocklist_gen application will randomly generate a blocklist for the given scenario file, and update that 
scenario file with the expected packet ratio to enable testing of the firewall (to see if it is blocking the packets we expect it to!)

To generate a new blocklist:

- Requires firewall.yaml scenario file (by default, can be changed in the application "SCENARIO_NAME" constant).
- The Scenario file must have been run atleast once, for sdn-cockpit to generate the schedule file.

Simply run blocklist_gen.py
(May need to 'pip install' a compatible yaml lib eg. PyYaml)
Note: It isn't necesary to generate a blocklist, I've provided one in the files.

**Security Goals & Project Summary**

The intention of this firewall application was that it would be used as a single component in a multilevel security strategy,
necessitating the firewall **1)** not cause undue additional latency, **2)** monitor incoming traffic and access relevant header information 
**3)** access a blocklist and **4)** deny / allow access based on 2/3.

These goals were achieved by:
1: Ensuring the firewall processes packets as fast as possible
    - Efficient data structure of blocklist
    - Efficient lookup method
    - Create flow rules for faster routing of subsequent traffic
2: Switch default flow rule to forward all traffic to the controller
    - Ryu lib used to access header information
3: Blocklist read in to local variable (dict) to be accessed when needed
4: Flow rules and packet forwarding / dropping were implemented based on header information and the blocklist