Welcome to my web crawler project designed to explore the world of web traversal using the HTTP protocol. 

The primary objective of this project is to construct a web crawler capable of navigating a simulated social networking site named Fakebook. This platform mimics real-world interactions and features a range of pages, from user profiles to friends' lists. To embark on this adventure, I employ a command-line interface with my crawler script, allowing seamless interaction through the terminal.

As the crawler commences its journey through Fakebook, it harnesses its ability to follow hyperlinks, systematically traversing the pages. A crucial detail is the hunt for five unique secret flags, each embedded within a distinctive student-specific context. These flags, presented in a consistent format, remain concealed within the HTML structure of the site. My crawler's task is to locate and extract these flags while adapting to the dynamic nature of Fakebook's pages.

It's essential to note that this project, while illuminating the prowess of web crawlers, also underscores ethical considerations. I restrict the testing of my crawler solely to Fakebook to avoid inconveniencing other web administrators. This aligns with industry norms and respects the resources of website hosts.

The diverse technical landscape of this assignment extends to the programming language selection. While adhering to compatibility with the Khoury College Linux machines, I've chosen Python to craft my crawler. This language empowers me to implement HTTP requests, parse HTML, and manipulate data efficiently. 

The code performs an initial GET request to the login page of the web server to obtain a session ID and a csrf token. Then, the code simulates a login by sending a POST request to the server that includes the username, password, csrf token, and session ID. If the login is successful, the server responds with a 200 OK code that contains another csrf token and session ID that are required for further requests.

After successful login, the code parses the HTML response using an HTML parser, extracting all the links found in the page, the csrf token, and the secret flags. The parser uses the handle_starttag method to identify the "a", "input", and "h2" tags and the handle_data method to extract the secret flag. The Crawler class, which is responsible for crawling the fakebook network, maintains a frontier, a set of visited links, and a list of secret flags. The frontier contains links that have not been visited, and the crawler visits each link in the frontier until all links have been visited. All the links that have been crawled will be added to the visited_links set to avoid loops.

The crawler sends a GET request to each link in the frontier and processes the response according to the HTTP status code. If the response is a 200 OK code, the HTML parser is invoked to extract links, the csrf token, and secret flags. If the response is a 302 redirect code, the crawler extracts the location header and sends another GET request to that location. If the response is a 404 Not Found or a 403 Forbidden code, the crawler abandons the link. If the response is a 503 Service Unavailable code, the crawler waits for a specified time and then retries the request.

The code uses the socket module to establish a TCP connection with the server and the ssl module to encrypt the connection. The urllib.parse module is used to parse URLs, and the deque class from the collections module is used to implement the frontier. The code also uses the HTMLParser class from the html.parser module to extract links and secret flags from the HTML response. The code maintains a list of secret flags that are extracted during the crawling process.



CHALLENGES FACED:

1. debugging was definitely something that we struggled with. An issue we kept running into was the program not exiting properly because the self.frontier queue and visited links weren't synchronzining efficiently.
2. Logging in was the hardest part of the assignment. It took us a while to figure out the login process.
3. Figuring out how the parser works took some research




TESTING:

The biggest thing that helped was probably using print statements. I used print statements to see where my code was reaching. I also used print statements to see what each variable was holding at any point. For example, it was useful to print out things like 'self.frontier', 'self.visited_links', and 'csrf_token' to help us with figuring out what was exactly going on and to see what each item contained.
