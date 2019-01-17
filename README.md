# uweb
A tiny multi-threaded http server for MacOS, Linux and Windows, released under GPLv2 !

uweb is designed to be a portable, static HTTP server, with high security, high performance and very small footprint.
uweb is written in pure C using portable stream file and socket API. 

- Have you ever wanted to set up a web server in a few seconds without spending hours in the documentation or consuming to much resources ?
- Do you want to know how to write a server based on the socket programming APIs, writing IPv4/IPv6 agnostic applications  ? Or managing a pool of worker threads ?
- Do you want a Web server that you can easily customize ? 
uweb is made for you !

### Set up for Linux and MacOS

get the source, compile, run :

    $ git clone https://github.com/PJO2/uweb
    $ make
    $ ./uweb -v


### set up for windows

Even easier : get the binaries and run !

    > git clone https://github.com/PJO2/uweb
    > WinBinaries\uweb32.exe -v

### test it
from a local web brower open this URL : http://127.0.0.1:8080/



