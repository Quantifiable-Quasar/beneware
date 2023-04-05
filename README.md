### Description

This is a script that will reach out to various network devices and perform a password spraying attack. From there, it will send a script to these devices to harden them.

### Useage

- the -h flag will detail all the options
- the -ip flag will specify the file which holds the IP list
- the -u flag will specify the file which holds the list of users to try
- the -p plag will specify the file which holds the list of passwords to try
- the -t flag will specify the timeout to use for SSH connections 
    - Setting a timer that is too low will cause valid logins to fail

### Todo

- add a verbose mode 
- implement concurency
- add a network scan if an IP list is not supplied
- write hardening scripts for unix
- write hardening scripts for windows
