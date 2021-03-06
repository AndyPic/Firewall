##TEST & EVALUATION README##

Multiple tests were run to determine the most efficient data structure and access/search method for the blocklist.

TL;DR - The best option was to have a blocklist with hashable data structure, load the blocklist in to memory at 
controller init, and use python 'in' keyword for hash table lookup.
Resulting in:

**POSITIVE**

- No latency for reading file in per-operation
- O(1) lookup efficiency due to hash table
- Scalable, as lookup efficiency doesnt decrease with data size

**NEGATIVE**

- Hashable data structure uses more memory (file size almost double)
- Blocklist loaded on init, program must be restarted to update the list.
	- Multi-threading solution to update on file change is possible, didn't get to implement though


**DETAILS**

Blocklists were generated using blocklist_gen.py
Scenario used to test was firewall.yaml
	1st test - 20 events, 5 packets each
	2nd test - 200 events, 5 packets each
Log file generated via log_time method in firewall.py
Binary search used the method binary_search in firewall.py

The FIRST TEST compared:

	1: A list of formatted ip addresses, as strings (eg. ["11.11.11.11", "22.22.22.22"])
	   Binary search method
	  
	2: A list of formatted ip addresses, as strings (eg. ["11.11.11.11", "22.22.22.22"])
	   Python 'in' keyword
	  
	3: A list of 32-bit integers to represent ip addresses (eg. [369112924, 369113360])
	   Binary search method
	  
	4: A list of 32-bit integers to represent ip addresses (eg. [369112924, 369113360])
	   Python 'in' keyword

Files were loaded in per-operation (Hence the relatively high latency in test 1, compared to test 2)

The raw data can be found in 'log.txt' file.
The average latency (in ms) and std deviations were:
	1:  Avg		= 40.75604897
		Std.D	= 1.50297733
	
	2:  Avg		= 47.66478125
		Std.D	= 2.041077492
		
	3:  Avg		= 29.39565853
		Std.D	= 1.232493909
		
	4:  Avg		= 24.9578266
		Std.D	= 1.353785382


<img src="https://gitlab2.eeecs.qub.ac.uk/40315028/csc7078-project-andrewpickard/raw/master/tests/imgs/Firewall_latency_graph.png" />

Fig. 1 - Stacked graph of relative latency for the different approaches in test 1.

These results indicate that the best performance is to use 32-bit integer with the binary search method.

The SECOND TEST build on the results of the first, and compared:

	1: A list of 32-bit integers to represent ip addresses (eg. [369112924, 369113360])
	   Python 'in' keyword

	2: A list of 32-bit integers to represent ip addresses (eg. [369112924, 369113360])
	   Binary search method
	  
	3: A dict of hashable key-value pairs of formatted ip adresses (key) and 32-bit int (value) 
	   (eg. {"22.0.0.67": 369098819, "22.0.0.217": 369098969})
	   Python 'in' keyword (No comparison with binary search, as it doesnt benefit from being hashable)

Blocklist file was loaded in on init, not per-operation.

The raw data can be found in 'log.txt' file.
The average latency (in ms) and std deviations were:

	1:  Avg		= 14.61832064
		Std.D	= 13.60858829
	
	2:  Avg		= 0.698440856
		Std.D	= 0.906103144
		
	3:  Avg		= 0.637944796
		Std.D	= 0.34912167
		
<img src="https://gitlab2.eeecs.qub.ac.uk/40315028/csc7078-project-andrewpickard/raw/master/tests/imgs/firewall_latency_graph_2.png" />

Fig. 2 - Stacked graph of relative latency for the different approaches in test 2.

These results indicate that the best combination for latency is to:
- Load the blocklist on init
- Use a hashable data structure with python 'in' keyword

The figure 2 (and the standard deviations) also demonstrate that using the hashable data structure reduces the variance in lookup times.

<img src="https://gitlab2.eeecs.qub.ac.uk/40315028/csc7078-project-andrewpickard/raw/master/tests/imgs/test_running.png" />

Fig. 3 - sdn cockpit while running the firewall.yaml scenario.
- Ryu pane shows the controller handling packets, setting flow rules and displays the time (ms) to process the packet.
- Scenario pane shows the details of the scenario, and that it was succesful (ie. the packets were dropped / forwarded as expected).
- Task pane shows the topology used.

**General functionality testing**
(ie. does the firewall block / allow the packets we expect it to)

Evaluation methods:

- Ryu pane (in sdn-cockpit) messages **(See Fig. 3 & 4)**
    - Due to print() statements within the controller, it is evident how the controller is handling packets
    - Message displayed on packet in, with source and destination info
    - Message displayed on new flow rule being set
        - Colour coded: Green = forward rule, Yellow = drop rule
- Scenario success / failure **(See Fig. 3 & 4)**
    - Packet ratio is set in the scenario file (by blocklist_gen.py) indicating the expected packets to be dropped / forwarded 
      during the scenario
    - Displays 'SUCCESS' if the actual packet ratio matches the expected packet ratio
    - Displays either fail / error if actual doesnt match expected + debug info
- Pings / hping3 / nmap / iperf **(See Fig. 4, 5 & 6)**
    - The ping command was used in mininet to initiate the controller setting up some flow rules, and check packet routing
    - iperf was used from xterm's to check conectivity, performance and load capability
        - n1 was set as iperf -s (server) n2-5 connect as iperf -c (clients)
- Wireshark was used to view individual packet behaviour **(See Fig. 6)**


<img src="https://gitlab2.eeecs.qub.ac.uk/40315028/csc7078-project-andrewpickard/raw/master/tests/imgs/mininet_pings.png" />

Fig. 4 - Shows the result of ping's between n1 and n2-5 (mininet pane) and the flow rule's being set (Ryu pane). 
traffic between n2, n3 and n1 is allowed (as defined within the blocklist.json) where traffic between n4, n5 and n1 is blocked as expected.

<img src="https://gitlab2.eeecs.qub.ac.uk/40315028/csc7078-project-andrewpickard/raw/master/tests/imgs/xterm_iperf.png" />

Fig. 5 - (Hard to see due to small xterms) Shows an iperf server running on n1, with n2-5 connecting as clients. n2 and n3 connect fine, where n4 and n5 are blocked.

<img src="https://gitlab2.eeecs.qub.ac.uk/40315028/csc7078-project-andrewpickard/raw/master/tests/imgs/wireshark_nmap.png" />

Fig 6. - Shows Wireshark capturing packets from n1, while xterm n2-5 use nmap (sudo nmap -sT 11.0.0.0 -Pn) to probe n1. n2 and n3 SYN / ACK as normal, 
where n4 and n5 are not able to connect to n1 so repeatedly ARP.
