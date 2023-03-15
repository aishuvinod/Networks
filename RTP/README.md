HIGH LEVEL APPROACH:
The high-level approach of the code to ensure data is delivered in order, without duplicates, missing data, or errors is as follows:

The Sender reads input data from standard input in chunks of 1375 bytes at a time and sends each chunk as a packet over a UDP socket to the Receiver, along with a sequence number and a checksum. It also initializes a timer for each sent packet.

The Receiver listens for incoming packets over the UDP socket, receives each packet, checks its checksum, and sends back an acknowledgement packet to the Sender indicating the sequence number it has received. If the Receiver receives a duplicate packet or a packet with a corrupted checksum, it ignores the packet and does not send an acknowledgement.

The Sender maintains a buffer of sent packets that have not yet been acknowledged, along with their sequence numbers and associated timers. If a packet's timer expires before it receives an acknowledgement, the Sender resends the packet and restarts the timer. If the Sender receives an acknowledgement for a packet, it removes the packet from the buffer.

The Sender limits the number of unacknowledged packets it has sent to a maximum window size of 4 packets at a time. If it has already sent the maximum number of packets and has not yet received an acknowledgement for any of them, it stops sending packets and waits for acknowledgements before sending more.


 

CHALLENGES FACED:

1. debugging was definitely something that we struggled with. An issue we kept running into was the program not exiting properly because the queue became full during retransmission.
2. The general idea of how to keep track of out of order packets and detect corrupt packets and duplicate packets was challenging
3. Understanding what aspects affected the performance tests was challenging


DESIGN:

1. Handling corrupted packets - We think the best property of this aspect of our code is that it is all in a try and catch block. A lot of the corrupted packets dont have the right format which stop it from being able to be loaded through json. So, putting the json.loads inside a try made sure to avoid that issue.
2. Timeouts and Sequence numbers - We efficiently keep track of each packet's start time and sequence number by making it a part of the message. This helped us effectively handle duplicate packets, out of order packets, and corrupt packets.
3. We initialized a dictionary of unacknowledged buffers which contains the sequence number of every packet sent and is removed when that packet receives an acknowledgment. Doing this helped us keep track of out of order packets, packets which have received an acknowledgment (which also helped us determining window size), retransmission, and also duplicate packets.
 
 
 
TESTING:

Here are some steps that we took to help us with testing and debugging:
1. The biggest thing that helped was probably using print statements. I used print statements to see where my code was reaching. I also used print statements to see what each variable was holding at any point. For example, it was useful to print out things like 'seq_num', 'msg_dict', and 'msg' to help us with figuring out what was exactly going on and to see what the routing table contained.
2. We Looked into the configs file and tried to understand the tests in order to better understand what was going on and why our tests weren't passing
