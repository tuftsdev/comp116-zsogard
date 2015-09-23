Zachary Sogard
COMP 116
Assignment 1

set1.pcap
1. 861 packets
2. FTP - File Transfer Protocol
3. The protocol is insecure because it is unencrypted (unlike SFTP) so all of the packets are in plaintext.
4. SFTP - Secure File Transfer Protocol
5. 192.168.1.8
6. Username: defcon, Password: m1ngisablowhard
7. 6 files
8. C0aqQWnU8AAwX3K.jpg
CDkv69qUsAAq8zN.jpg
CNsAEaYUYAARuaj.jpg
CLu-m0MWoAAgjkr.jpg
CKBXgmOWcAAtc4u.jpg
CJoWmoOUkAAAYpx.jpg
9. files attached

set2.pcap
10. 77982 packets
11. 1 pair: larry@radsot.com:Z3lenzmej
12. I used a filter in Wireshark: eth matches "LOGIN|password|username|success|Password|Username|login" to find packets that contain any one of these keywords.
13. Protocol: IMAP
Server IP: 87.120.13.118
Server hostname: 76.0d.78.57.d6.net
Server port number: 143
14. 1 pair was legitimate because the server sent a successful response back "OK LOGIN Ok."

set3.pcap
15. seymore:butts
nab01620@nifty.com:Nifty->takirin1
16. seymore: Protocol: HTTP, Server IP: 162.222.171.208, Server hostname: forum.defcon.org, Server port number: 80
nab01620@nifty.com: Protocol: IMAP, Server IP: 210.131.4.155, Server hostname: not found using nslookup or dig, Server port number: 143
17. 1 pair was legitimate: seymore's were not valid and access was denied with HTTP 403 Forbidden
nab01620@nifty.com's was valid because the server sent a successful "OK LOGIN Ok." response
18. lga15s47-in-f0.1e100.net (173.194.123.32)
map2.hwcdn.net (205.185.216.10)
unknown.interbgc.com (217.9.235.145)
ec2-54-85-144-106.compute-1.amazonaws.com (54.85.144.106)
barracuda.com (64.235.154.33)
control-wc.adap.tv (64.236.122.10)
pixel.quantserve.com (64.95.32.31)
host82.maxhealth.com (65.215.51.82)
p3plpop05-v01.prod.phx3.secureserver.net (97.74.135.218)
a.it.vip.ne1.yahoo.com (98.138.47.63)
a1507.b.akamai.net (23.61.194.184)
a769.phobos.g.aaplimg.com (17.253.16.222)
api.smoot-apple.com.akadns.net (17.249.25.246)
api.twitter.com (199.16.156.104)
appspot.l.google.com (74.125.28.141)
archive.linux.duke.edu (152.3.102.53)
forum.defcon.org (162.222.171.208)
mirror.us.leaseweb.net (108.59.10.97)
s3-1.amazonaws.com (54.231.16.224)
star.c10r.facebook.com (173.252.110.27)

My methodology was to enable the resolve IP addresses option in Wireshark and look at each unique resolved IP.
General Questions:
19. Follow the TCP stream associated with the packet and look for a server's response indicating a successful login such as "success", "access granted", "login ok", etc.
20. The owners of these pairs should use encrypted or secure protocols instead of the ones they used. For example use HTTPS instead of HTTP, SFTP instead of FTP, etc.
