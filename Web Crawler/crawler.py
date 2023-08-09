#!/usr/bin/env python3

import argparse
import socket
import ssl
import urllib.parse
from html.parser import HTMLParser
from collections import deque
import time



DEFAULT_SERVER = "proj5.3700.network"
DEFAULT_PORT = 443
secret_flags = [] # keep track of flags


# html parser class
class MyHTMLParser(HTMLParser):
    # keep track of all links
    links = {}
    csrf_token = ""
    is_secret_flag = False

    def handle_starttag(self, tag, attrs):
        # look for anchor tags that indicate a link within
        if tag == 'a':
            # only parse links which are within the fakebook domain
            if '/fakebook/' in attrs[0][1]:
                # extract the link and provide a key value
                link = attrs[0][1]
                self.links[link] = 1
        

        if tag == 'input':
            # extract csrf middleware token
            if attrs[1][1] == 'csrfmiddlewaretoken':
                self.csrf_token = attrs[2][1]
        # set secret flag to true if a flag is found
        if tag == 'h2' and ('class', 'secret_flag') in attrs:
            self.is_secret_flag = True
    # strip the flag value and append it to the list of secret flags
    def handle_data(self, data):
        if self.is_secret_flag:
            flag = data.strip()
            if flag.startswith("FLAG: "):
                secret_flags.append(flag[6:])
            

    # helper to get links
    def get_links(self):
        return self.links

    # helper to get csrf token 
    def get_csrf(self):
        return self.csrf_token
    
    # return the secret flags
    def get_secret_flags(self):
        return self.secret_flags

   
    
        

class Crawler:

    def __init__(self, args):
        self.server = args.server
        self.username = args.username
        self.password = args.password
        self.socket = None
        self.visited_links = set()
        self.frontier = deque()
        self.csrf = None
        self.sessionid = None
        
    # helper method for sending request when recieving 302 code
    # retry request by using the path in the location header in the http response
    def found_302(self, response):
        location = response.split("Location: ")[1].split("\r\n")[0]
        if "csrftoken=" in response:
            self.csrf = response.split("csrftoken=")[1].split(";")[0]
        if "sessionid=" in response:
            self.sessionid = response.split("sessionid=")[1].split(";")[0]
        recieved = self.send_GET(location, self.csrf, self.sessionid)
        return recieved

    # helper to send a get request   
    def send_GET(self, location, csrf, sessionid):
        socket = self.socket
        request = f"GET {location} HTTP/1.1\r\nHost: {self.server}\r\nConnection: Keep-Alive\r\nCookie: csrftoken={csrf}; sessionid={sessionid}\r\n\r\n"
        socket.send(request.encode('ascii'))
        data = socket.recv(4000)
        recieved = data.decode('ascii')
        return recieved
    
    # helper to handle different error codes 
    def code_handlers(self, post_recieved):
        
            # Handle 302 redirect and call the helper
            if "HTTP/1.1 302 Found" in post_recieved:
                post_recieved = self.found_302(post_recieved)
                return self.code_handlers(post_recieved)
            
            # handle 404 or 403 and automatically abandon url
            elif "404 Not Found" in post_recieved or "403 Forbidden" in post_recieved:
                return "Not Found"
                
            # retry a 503 unavailable request 
            # the retry is handled within the while crawl
            elif "HTTP/1.1 503" in post_recieved:
                return "retry"
                
            # a successful request with a 200 status code
            elif "200 OK" in post_recieved:
                if "csrftoken=" in post_recieved:
                    self.csrf = post_recieved.split("csrftoken=")[1].split(";")[0]
                if "sessionid=" in post_recieved:
                    self.sessionid = post_recieved.split("sessionid=")[1].split(";")[0]
                return post_recieved



    def run(self):
        start_time = time.time()
        
        # make a connection to the default port if specified otherwise using the -p flag
        if not args.port:
            self.port = DEFAULT_PORT
        else: 
            self.port = args.port

        #open up tcp socket and form an ssl connection
        mysocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self.port == DEFAULT_PORT:
            context = ssl.create_default_context()
            mysocket = context.wrap_socket(mysocket, server_hostname=self.server)
        mysocket.connect((self.server, self.port))
        self.socket = mysocket
        
        # create first get request to login page
        first_getrequest = "GET /accounts/login/ HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\n\r\n" % self.server
        
        # send request and receive response
        mysocket.send(first_getrequest.encode('ascii'))
        data = mysocket.recv(4000)
        session_info = data.decode('ascii')
        if "csrftoken=" not in session_info:
            mysocket.send(first_getrequest.encode('ascii'))
            data = mysocket.recv(4000)
            session_info = data.decode('ascii') 
        

        # extract session info and csrf token for login purposes
        if "csrftoken=" in session_info:
            self.csrf = session_info.split("csrftoken=")[1].split(";")[0]
        if "sessionid=" in session_info:
            self.sessionid = session_info.split("sessionid=")[1].split(";")[0]
        if 'csrfmiddlewaretoken" value="' in session_info:
            csrf_middle = str(session_info.split('csrfmiddlewaretoken" value="')[1].split('"')[0])
       
        # put login info into an object and encode it to send as part of the request
        login = {
                'username': self.username,
                'password': self.password,
                'csrfmiddlewaretoken': csrf_middle,
                'next': '/fakebook/'
            }

        login_request = urllib.parse.urlencode(login)
        
        # send post request with encoded login info and receive the response 
        request = f"POST /accounts/login/ HTTP/1.1\r\nHost: {self.server}\r\nConnection: Keep-Alive\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {str(len(login_request))}\r\nCookie: csrftoken={self.csrf}; sessionid={self.sessionid}\r\n\r\n{login_request}"
 
        mysocket.send(request.encode('ascii'))
        data = mysocket.recv(4000)
        post_recieved = data.decode('ascii')
        # handle any error codes that could arise from login post request 
        response = self.code_handlers(post_recieved)
        
        # provide parser with links received from the post request response and add the links to the frontier queue containing all the links that need to be crawled
        parse = MyHTMLParser()
        parse.feed(response)
        links = parse.get_links()
        self.frontier.extend(links)
        
        # continue crawling through links in queue until it is empty
        while len(self.frontier) != 0:
            try:
                queue = self.frontier 
                link = queue.pop() # pop the next link to crawl
                response = self.send_GET(link, self.csrf, self.sessionid) # send get request  
                recieved_html = self.code_handlers(response)
                
                # for an 503 error code  ; retry request that was sent above
                while recieved_html == "retry":
                    response = self.send_GET(link, self.csrf, self.sessionid)          
                    recieved_html = self.code_handlers(response)
                # add link that was crawled to the set of links that are already crawled
                self.visited_links.add(link)

                if recieved_html != None:
                #reparse response from the link that was just crawled and add it to the queue         
                    parse = MyHTMLParser()
                    parse.feed(recieved_html)
                    links = parse.get_links()           
                    for path in links:
                        #AVOID RECRAWL
                        if path not in self.visited_links:
                            queue.append(path)   
                                 
                # check for secret flags
                parse = MyHTMLParser()
                if secret_flags:
                    if len(secret_flags) >= 5:
                        for flag in secret_flags:
                            print(flag)
                            
                        # print("\nSuccess! Found all 5 flags\n")
                        # print(f"--- Crawled in {time.time() - start_time} seconds ---")
                        break
                
                # if connection of socket breaks
            except BrokenPipeError as e:
                # print("CONNECTION STOPPED... RECONNECTING")
                
                # open new socket
                mysocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                if self.port == DEFAULT_PORT:
                    context = ssl.create_default_context()
                    mysocket = context.wrap_socket(mysocket, server_hostname=self.server)
                mysocket.connect((self.server, self.port))
                self.socket = mysocket
            except ssl.SSLEOFError as e:
                # reform ssl connection
                mysocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                if self.port == DEFAULT_PORT:
                    context = ssl.create_default_context()
                    mysocket = context.wrap_socket(mysocket, server_hostname=self.server)
                mysocket.connect((self.server, self.port))
                self.socket = mysocket
                
                # retry again with the link
                self.frontier.append(link)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='crawl Fakebook')
    parser.add_argument('-s', dest="server", type=str, default=DEFAULT_SERVER, help="The server to crawl")
    parser.add_argument('-p', dest="port", type=int, help="The port to use")
    parser.add_argument('username', type=str, help="The username to use")
    parser.add_argument('password', type=str, help="The password to use")
    args = parser.parse_args()
    sender = Crawler(args)
    sender.run()
