
HIGH LEVEL APPROACH:

Our high level approach is to continuously monitor the sockets for incoming messages using a while loop and the select module. When a message is received, the router determines its type (handshake, dump, update, or data) and takes the appropriate action. For handshake messages, the router sends a handshake response back to the sender. For dump messages, the router sends the routing table to all neighbors. For update messages, the router updates its routing table, aggregates routes, and forwards the message to other routers as appropriate based on their relationships. For data messages, the router looks up the destination IP address in the routing table, selects the best matching route, and forwards the message to the next hop specified in that route. For withdraw, the code removed the entry from the routing table and disaggregates any aggregation that may have happened.

 

CHALLENGES FACED:

1. debugging was definitely something that we struggled with. Especially, with the sending rules and between all the variables whether it be neighbor, peer, destination, etc, there were a lot of small issues that were causing my code to not work properly.
2. The general idea of how a router works and wrapping my head around what was going on took some time
3. Understanding how aggregate and disaggregate works along with with the ip adresses being numerically adjacent defintiely took some time to understand. 
4. Longest prefix match was also challenging to implement.


DESIGN:

1. We think the best property of my code is that it is all in a try and catch block. All of our if message = "_" exists inside the try and if something fails in that code, my code will jump to catching the error and also help with the traceback of the error.
2. Our routing table is intialized as an array which we think worked well
3. I extract all components of a message and put into variables to make the code cleaner and help with clarity
4. I also extract all the components of a message when I send so that I can just send it as an object inside the message field. This helped with clarity as well.
 
 
 
TESTING:

Here are some steps that we took to help us with testing and debugging:
1. The biggest thing that helped was probably using print statements. I used print statements to see where my code was reaching. I also used print statements to see what each variable was holding at any point. For example, it was useful to print out things like 'best_route', 'msg', and 'self.routing_table' to help me with figuring out what was exactly going on and to see what the routing table contained.
2. I used this code to help me debug. All my code is in a try catch and by inserting this piece of code,  I was able to find what error was causinf my code to not work correctly, and the traceback to it so I could find the line throwing the error.
except Exception as err :
                    print("Received invalid message '%s' from %s" %
                          (msg, srcif))
                    print(err)
                    print(traceback.format_exc())
3. Looked into the configs file and tried to understand the tests in order to better understand what was going on and why my tests were'nt passing
