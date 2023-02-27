My program starts off by using the socket, argparse, and urllib.parse imports. The code is set up to connect to the FTP server ftp.3700.network on port 21. My program can run operations through the command line in this format, ./client <operation> <param1> <param2> where parameter1 is required and parameter2 is optional.
Here, the possible operations are: 
mkdir: creates a new directory on the FTP server. The param1 value is used as the name of the directory.
rmdir: removes an existing directory on the FTP server. The param1 value is used as the name of the directory.
ls: lists the contents of a directory on the FTP server. The param1 value is used as the path to the directory.
rm: deletes a file on the FTP server. The param1 value is used as the path to the file.
cp: copies a file from one location to another on the FTP server. The param1 value is used as the source file, and the param2 value is used as the destination.
mv: moves a file from one location to another on the FTP server. The param1 value is used as the source file, and the param2 value is used as the destination.

The high-level approach in this program is to establish a data channel in addition to the control channel between the client and the server in an FTP (File Transfer Protocol) connection. This is done by sending a "PASV" command to the FTP server through the control socket, which will then respond with the host and port information needed to connect to the data channel. The code then extracts the host and port information from the response, calculates the port number, and creates a new data socket that connects to the data channel using the host and port information.
The list_channel function takes the path of the directory to be listed as an input. The function opens a new data channel by calling the open_data_channel function and then sends a "LIST" command to the control socket along with the path of the directory. The control socket then receives a response from the server and passes it to the data socket, which receives and decodes the data. The contents of the directory are then printed. The data socket is then closed.
For dwonloading and uploading, I check to see if the beginning of the path starts with "ftp://". If it is, then I download it. If not, then I upload it.


The hardest part of this assignment for me was figuring out how the control and data channels work and how to switch between them. It specifically took me a while to understand the idea of how you still need to enter passive mode on the control channel, receive it on the control channel, send and receive list on the control channel, and also receive list on the data channel. It also took me a while to realize that I had parse the input. I had to read through the assignment multiple times to identify that I needed to import and use urllibparse. 

I tested the functionality of my code by using print statements to check what was being printed at eat stage and what statements were being received. I also logged on to the server each time I entered a command to check that it the operation was correctly being reflected on the server.
