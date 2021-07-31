**TESTS README**

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

Fig. 2 (and the standard deviations) also demonstrate that using the hashable data structure reduces the variance in lookup times.
