My program starts off by setting up a socket connection between the host and port. It then sends a "hello" message to the server and receives a response which is a JSON object. I then extract the "id" field from the JSON object and stores it in a variable called "id" which will be used for subsequent messages. I use a similar style of storage for 'guesses' and 'marks' as well.
I then read in a list of words from a file called 'project1words.txt' and store it as an array. The words are read in as a single string and are split on newlines to create a list of words


The logic of my guessing surrounds around using the returned marks. I create a new list and iterate over each word in the original word list. For each word, we check if it should be included in the new list based on the marks and word given. If it should be included, we add it to the new list. I do this by having an "include" variable which is initially set to true. When a condition is something that I dont want, I set the variable to false. At the end, I append all the words that are included in true to the new list.
Essentially:
If the marks are 0, then words with the corresponding letter wont have any words with that letter.
If the marks are 1, then words with that coressponding letter only in different spots will be added.
Finally, if the marks are 2, words that dont have the correspond letter in the right spot won't be added.

I send guesses by using a loop. The loop starts by creating an iterator for the list of words and an empty set to store already guessed words. Within the loop, it retrieves the next word from the iterator, checks if the word has already been guessed and if not, sends a guess message to the server, receives a reply and decodes it. If the reply is a "retry" message, it updates the list of words by removing the words that don't match the marks and word of the last guess and updates the iterator to iterate over the updated list. If the reply is a "bye" message, it prints the flag and breaks out of the loop. Finally, it closes the socket connection.

The hardest part of this assignment for me was figuring out how the connection between the client and server works. It took me a while to understand the idea of JSON and how I had to set up the socket, both TLS encrypted and non encrypted. It took a lot of research to figure out that this process would involve encoding, decoding, loading, etc. All the websites that I used as resources and to read up on and have been included in my oode under references.

I tested the functionality of my code by using print statements to check what words were being printed and what statements were being received. I also tried to test my code with some smaller wordlists.
