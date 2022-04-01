# size_t OSCP notes - in C++! 

Offensive security students will often write an "OSCP cheatsheet" to document the commands they use, helpful links, methodology, etc. for reference. This is a great idea, because not only does it help them by documenting things they can reference later, but they can also help other students who can also use it as a reference!

I have taken this one step further and written a simple command line tool with a menu, that has options for things like reverse shells. So the idea is that you no longer need to go and google around for cheatsheets and scroll down for ages to find something. Instead, you can just run this very fast tool, find what you're looking for and it will print it to the terminal!

This tool is a working progress and will be constistantly worked on and updated.

### How to use it?

It's very simple and fast, grab the source code, compile and run it from a CLI. Keep it around for when you want to use it.

```bash
g++ size_t-cheatsheet.cpp -o size_t-cheatsheet --std=c++20
```

### Dependencies? 

None, this will compile and run cross-platform (windows, linux, etc). 

It's only dependency is that you compile it as C++20, because it has some more modern C++ features in the code.

## Features

### Reverse Shell One Liners

* Bash reverse shells
* Perl reverse shells
* Python reverse shells
* php reverse shells
* Ruby reverse shells
* Netcat reverse shells
* Java reverse shells
* xterm reverse shells
* Powershell reverse shells
* C reverse shell (1)


### Bind shell One Liners

* Perl bind shells
* Python bind shells
* php bind shells
* Ruby bind shells
* Traditional netcat bind shells
* Netcat openbsd bind shell
* Socat bindshell


### HTTP Servers

* Python2 HTTP server
* Ruby HTTP server
* Python3 HTTP server
* php HTTP server
* busybox HTTP server


### Buffer Overflow Skeleton PoC's

* Python2 skeleton PoC
* Python3 skeleton PoC
* Bad char generator (256)

### Linux post enumeration

* TTY spwan shell
* Cron Jobs enumeration
* Sudo privesc
* Service enumeration



### Credits
I couldn't have written it without the following peoples work and ideas:
* cwinfosec
* secoats
* swisskyrepo
