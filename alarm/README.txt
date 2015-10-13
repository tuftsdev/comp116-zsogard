README.txt
Zachary Sogard
Comp 116 - Fall 2015


###Identify what aspects of the work have been correctly implemented and what have not.###
Correctly implemented:
Searching log file for shellcode, shellshock, masscan, nikto, nmap, phpMyAdmin
Live scanning for TCP FIN, ACK, and NULL scans
Detecting credit cards in the clear

Unsure if correctly implemented:
"Other" nmap scans (including UDP-based) because the payload is often empty
Nikto scans for the same reason

Tested by running nmap against localhost with various flags, and having alarm.rb listen on the "lo" (loopback) interface

###Identify anyone with whom you have collaborated or discussed the assignment.###
I have discussed the assignment with Alex Goldschmidt and Ben deButts (former student) on how to test the assignment.

###Say approximately how many hours you have spent completing the assignment.###
5-6 hours


###Are the heuristics used in this assignment to determine incidents "even that good"?###
The heruistics are good for detecting NULL, FIN, and ACK scans. However detecting other nmap or nikto scans
is hit or miss because the payload may be empty and not contain the identifying string. The credit card scan,
shellcode scan, and shellshock vulnerability scan heuristics are decent but can detect many false positives
like things that look like credit card numbers or the typical shellshock string but aren't.

###If you have spare time in the future, what would you add to the program or do differently with regards to detecting incidents?###
There are other types of nmap scans such as a SYN scan, ACK scan, and Maimon scan that I would add. Additionally, I would look
more closely at the fingerprints used to commonly identify Nikto and Nmap scans.


