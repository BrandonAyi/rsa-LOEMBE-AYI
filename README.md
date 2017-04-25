README


included:

source file (MyAdBlock.c)
this README
Makefile
black_list.txt : file containing the banned sites list (list from https;//easylist.to/)


How to use it:

You first have to configure your web navigator in order to use the proxy.
Select the manual proxy configuration : HTTP proxy address which is localhost (127.0.0.1) and the port number you want to use.

Then in the terminal, compile the file MyAdBlock.c by a make. The exec file is named "block" but you can change it in the Makefile.
Run the proxy with : ./block <port number> 
Example : ./block 2222

Then you should have this in the terminal : 

- - - - - - - - - - - - - - - - - - - - - - -
- - - - - - - - PROXY SERVER BY - - - - - - - -
- - - - - - - - - ALEX-KEVIN - - - - - - - - -
- - - - - - - - - - - AND - - - - - - - - - - -
- - - - - - - - - - BRANDON - - - - - - - - - -
- - - - - - - - - NOW RUNNING - - - - - - - - - 
- - - - - - - - - - - - - - - - - - - - - - - -

The proxy is running ! You can now go on the internet !