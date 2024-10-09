### Description

This program will brute force SSH servers on a given network, and once connected, send hardening scripts. This project was inspired by the Mirai botnet, so the initial access is pretty much copied from them. Instead of sending malware, however, this sends hardening scripts. 

### Install

```bash
git clone https://github.com/Quantifiable-Quasar/beneware.git
cd beneware
go mod download
go run main.go
```

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
- make windows work
- create client agent to deploy on host to maintain connections
