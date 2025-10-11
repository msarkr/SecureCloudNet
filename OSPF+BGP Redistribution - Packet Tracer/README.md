This network shows how two different routing protocols, OSPF and BGP, can share routes so both sides of a network can talk to each other.
The left side represents an internal company network running OSPF, and the right side represents an external or partner network running BGP.
The middle router connects the two and passes route information between them so that every device can reach one another.

On the left, the OSPF LAN uses the network 192.168.1.0/24.
Two PCs (192.168.1.2 and 192.168.1.3) connect through a switch to an OSPF router whose gateway address is 192.168.1.1.
This router advertises its network to the redistribution router using OSPF.

The redistribution router runs both OSPF and BGP.
It learns the internal OSPF routes and also communicates with the BGP router on the right.
By redistributing what it learns from OSPF into BGP and vice versa, it lets both routing domains share their network information.
That’s what allows pings to succeed between the two LANs even though they use different routing protocols.

On the right, the BGP LAN uses 172.16.20.0/24.
Two PCs (172.16.20.2 and 172.16.20.3) connect through a switch to a BGP router with a gateway of 172.16.20.1.
This router runs BGP in AS 65002 and advertises its network to the redistribution router, which belongs to AS 65001.

When everything is configured correctly, a computer on the OSPF side can ping a computer on the BGP side because each router knows how to reach the other network.
The OSPF router learns about 172.16.20.0/24 through redistribution, and the BGP router learns about 192.168.1.0/24 the same way.

You can check your setup with a few basic commands:
use “show ip route” to see if both networks appear,
“show ip ospf neighbor” to confirm OSPF connectivity,
“show ip bgp summary” to confirm BGP peering,
and then ping across the LANs to prove full reachability.