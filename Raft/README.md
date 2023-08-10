HIGH LEVEL APPROACH
The Raft protocol is a consensus algorithm for distributed systems, ensuring nodes agree on data even during failures. It uses a leader-follower model, where one leads the process, coordinating log replication. Raft simplifies complex tasks like leader election and maintains data consistency, making it a reliable choice for distributed system reliability.
Compared to some other consensus algorithms, Raft aims to be more understandable and straightforward, which facilitates its implementation and troubleshooting. Its clear separation of roles and well-defined rules for leader election and log replication make it an attractive choice for building reliable and fault-tolerant distributed systems.
Leader election -
- I created an enum so that I could establish the three states of the Raft as follower, candidate or leader. I made three if statements that implement the details for each state.

- LEADER: Send heartbeats consistently
- FOLLOWER: Keep checking for heartbeats and if you dont get heartbeats from the leader, elect yourself as the candidate. Increase the current term, vote for yourself, and broadcast a request to get votes.
- CANDIDATE : If you have the majority votes, make yourself the leader. If you dont or if the election has timed out, then, restart the election.
**I made helpers to start an election and send heartbeats

- Handled messages like "RequestVote" and "VoteResponse" within if statements. If you get a requestvote message, then either grant a vote or not by checking to see the term. If you get a VoteResponse, then check your votecount, increase it, and decide whether youre the leader or not.

- GET AND PUT MESSAGES : made a store dictionary with a key value property so that when you get a get message, the leader will check to see if it exists and sends an ok or fail message. If you receive a get or put message and youre not the leader, then redirect.


CHALLENGES
- figuring out the whole idea of a distributed system works with all the states took some reading
- had to read the raft paper a couple times
- timeout was confusing

TESTING
- used a lot of print statements to see what my store had at different time
- used the simulator to see what messages were being received, the output under the correctness checks, and the simulator errors.

GOOD DESIGN
- I think the enum style of state was a good idea. It was easy for me to call RaftState."" whenever I needed.
- I liked that I have variables to track, "votes_received", "timeout", etc
- I like that I have helpers to start election and send heartbeats since I use it multiple times
