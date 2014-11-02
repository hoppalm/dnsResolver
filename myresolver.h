/*
 * Authors: Rawlin Peters and Michael Hoppal
 * awget.h
 * 9-22-14
 *
 * Header file containing all function implementation for awget.cc and ss.cc
 */

#ifndef MYRESOLVER_H_
#define MYRESOLVER_H_

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <fstream>
#include <time.h>

using std::string;
using std::stringstream;
using std::vector;
using std::cout;
using std::endl;
using std::cerr;
using std::isdigit;
using std::getline;
using std::cin;
using std::remove;
using std::ifstream;
using std::istream;
using std::istringstream;

#define BUFFERSIZE 512

// from project 1
vector<string> &split(const string &s, char delim, vector<string> &tokens);
vector<string> split(const string &s, char delim);
bool _isNumber(const string &s);
bool _isDigitsOrDots(const string &s);
bool isValidIP(const string &s);
void *get_in_addr(struct sockaddr *sa);
string getHostIP();
string getHostname();
int getPortFromSocket(int sock);
int serverCreateSocketBindAndListen(const string& port);
int serverCreateSocketBindAndListen();
int clientCreateSocketAndConnect(const string& server_IP, const string& port);
int serverAcceptNewConnection(int sock);

// sending and receiving
void sendString(const string &s, int socket);
int sendAll(const char * data, int * lengthOfString, int socket);
string recvAll(int socket);
string recvString(int socket);
void sendURL(const string &URL, int socket);
string recvURL(int socket);

//This project
void myresolver(string URL, string recordType);
void populateRootServers();
vector<string> IPv4RootServers;
vector<string> IPv6RootServers;



/*
 * populates the root server vectors
 */
void populateRootServers(){
    IPv4RootServers.push_back("192.5.5.241");
    IPv4RootServers.push_back("192.112.36.4");
    IPv4RootServers.push_back("128.63.2.53");
    IPv4RootServers.push_back("192.36.148.17");
    IPv4RootServers.push_back("192.58.128.30");
    IPv4RootServers.push_back("193.0.14.129");
    IPv4RootServers.push_back("199.7.83.42");
    
    IPv6RootServers.push_back("2001:500:2f::f");
    IPv6RootServers.push_back("2001:500:1::803f:235");
    IPv6RootServers.push_back("2001:7fe::53");
    IPv6RootServers.push_back("2001:503:c27::2:30");
    IPv6RootServers.push_back("2001:7fd::1");
    IPv6RootServers.push_back("2001:500:3::42");
}

/*
 * Split a string into tokens based upon the delimiter
 * and add the tokens to the given vector<string>.
 */
vector<string> &split(const string &s, char delim, vector<string> &tokens) {
	stringstream ss(s);
	string token;
	while (getline(ss, token, delim)) {
		tokens.push_back(token);
	}
	return tokens;
}

/*
 * Split a string into tokens and return them as a vector<string>
 */
vector<string> split(const string &s, char delim) {
	vector<string> tokens;
	split(s, delim, tokens);
	return tokens;
}

/*
 * Return true if the string contains all digits
 */
bool _isNumber(const string &s) {
	string::const_iterator it = s.begin();
	while (it != s.end() && isdigit(*it)) ++it;
	return !s.empty() && it == s.end();
}

/*
 * Return true if the string consists of digits or dots (like an IPv4 address)
 */
bool _isDigitsOrDots(const string &s) {
	string::const_iterator it = s.begin();
	while (it != s.end() && (isdigit(*it) || *it == '.')) ++it;
	return !s.empty() && it == s.end();
}

/*
 * Return true if the string is a valid IPv4 address, i.e. 1.2.3.4
 */
bool isValidIP(const string &s) {
	if (!_isDigitsOrDots(s)) {
		return false;
	}
	vector<string> parts = split(s, '.');
	if (parts.size() != 4) {
		return false;
	}
	for (unsigned int i = 0; i < parts.size(); i++) {
		string curr = parts.at(i);
		if (curr.empty() || atoi(curr.c_str()) > 255) {
			return false;
		}
	}
	return true;
}

/*
 * Used for DEBUG
 */
void *get_in_addr(struct sockaddr *sa) {
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/*
 * Return the IP address of the host (not the 127.0.0.1 address),
 * or return empty string if no other address
 */
string getHostIP() {
	struct ifaddrs *if_addr_struct = NULL;
	struct ifaddrs *ifa = NULL;
	void *addr = NULL;

	getifaddrs(&if_addr_struct);

	for (ifa = if_addr_struct; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family == AF_INET) {
			addr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
			char addr_buffer[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, addr, addr_buffer, INET_ADDRSTRLEN);
			if (string(addr_buffer) == "127.0.0.1") continue;
			if (if_addr_struct != NULL) freeifaddrs(if_addr_struct);
			return string(addr_buffer);
		}
	}
	return "";
}

/*
 * Return the hostname of this machine
 */
string getHostname() {
	char hostname[128];
	gethostname(hostname, sizeof hostname);
	return string(hostname);
}

/*
 * Return the port number of a bound socket or -1 for an error
 */
int getPortFromSocket(int sock) {
	struct sockaddr_in sa;
	socklen_t sa_len;
	sa_len = sizeof(sa);
	if (getsockname(sock, (struct sockaddr*)&sa, &sa_len) == -1) {
		return -1;
	}
	//cout << "DEBUG: PORT: " << ntohs(sa.sin_port) << endl;
	return (int) ntohs(sa.sin_port);
}

/*
 * Return a bound, listening, server socket on the given port or exit on failure
 */
int serverCreateSocketBindAndListen(const string &port) {
	int rv, sock;
	int yes = 1;
	struct addrinfo hints, *server_info, *p;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if ((rv = getaddrinfo(NULL, port.c_str(), &hints, &server_info)) != 0) {
		cerr << "getaddrinfo: " << gai_strerror(rv) << endl;
		exit(1);
	}
	for (p = server_info; p != NULL; p = p->ai_next) {

		if ((sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol))
				== -1) {
			cerr << "server: create socket failed" << endl;
			continue;
		}

		if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int))
				== -1) {
			cerr << "server: setsockopt failed" << endl;
			exit(1);
		}

		if (bind(sock, p->ai_addr, p->ai_addrlen) == -1) {
			close(sock);
			cerr << "server: bind failed" << endl;
			continue;
		}

		//struct sockaddr_in *ip = (struct sockaddr_in *)p->ai_addr;
		//void *addr = &(ip->sin_addr);

		//inet_ntop(p->ai_family, addr, s, sizeof s);
		//cout << string(s) << endl;

		break;
	}
	if (p == NULL) {
		cerr << "ERROR: server failed to bind" << endl;
		exit(2);
	}
	freeaddrinfo(server_info);
	if (listen(sock, 10) == -1) {
		cerr << "listen" << endl;
		exit(1);
	}

	return sock;
}

/*
 * Same as above, but using a random available port
 */
int serverCreateSocketBindAndListen() {
	return serverCreateSocketBindAndListen("");
}

/*
 * Using a server socket, return a new socket from an accepted connection
 */
int serverAcceptNewConnection(int sock) {
	char s[INET6_ADDRSTRLEN]; // for DEBUG
	int new_sock;
	struct sockaddr_storage their_addr;
	socklen_t sin_size;
	sin_size = sizeof their_addr;
	new_sock = accept(sock, (struct sockaddr*) (&their_addr), &sin_size);
	if (new_sock == -1) {
		cerr << "accept" << endl;
		exit(1);
	}

	inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
	//cout << "DEBUG: ss got connection from " << string(s) << endl;

	return new_sock;
}

/*
 * Create a client socket and connect to a server at the given IP and port number.
 */
int clientCreateSocketAndConnect(const string& server_IP, const string& port) {

	int rv, sock;
	struct addrinfo hints, *server_info, *p;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if ((rv = getaddrinfo(server_IP.c_str(), port.c_str(), &hints,
			&server_info)) != 0) {
		cerr << "getaddrinfo: " << gai_strerror(rv) << endl;
		exit(1);
	}
	//cout << "Connecting to server..." << endl;
	for (p = server_info; p != NULL; p = p->ai_next) {
		if ((sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol))
				== -1) {
			cerr << "client: create socket failed" << endl;
			continue;
		}

		if (connect(sock, p->ai_addr, p->ai_addrlen) == -1) {
			close(sock);
			cerr << "client: connect failed" << endl;
			continue;
		}

		break;
	}
	if (p == NULL) {
		cerr << "client: failed to connect" << endl;
		exit(2);
	}
	freeaddrinfo(server_info);
	return sock;
}


/*
 *Primary function for ss

void steppingStone(const string &port) {

	string hostIP = getHostIP();
	int serverSocket = serverCreateSocketBindAndListen(port);
	int serverPort = getPortFromSocket(serverSocket);
	int newSocket;

	cout << "ss " << hostIP << " " << serverPort << ":" << endl;

	while (true) {
		newSocket = serverAcceptNewConnection(serverSocket);
		pthread_t newThread;
		if (pthread_create(&newThread, NULL, handleNewConnection, &newSocket)) {
			cerr << "ERROR: unable to create thread" << endl;
			exit(1);
		}
	}
}
 */

/*
 * Send a string to a socket
 * (to be used in sendURL and sendChainfile)
 */
void sendString(const string &s, int socket) {
	const char * data = s.c_str();
	int lengthOfString = strlen(data);
	sendAll(data, &lengthOfString, socket);
}


/*
 * Make sure that all of the data is being sent across the wire
 */
int sendAll(const char * data, int * lengthOfString, int socket) {
	int totalBytesSent = 0;
	int bytesRemaining = *lengthOfString;
	int numberOfBytesSent;

	//send length of string first
	int length = htons(*lengthOfString);
	if (send(socket, &length, sizeof(length), 0) < 0) {
		cerr << "Debug: Error sending string length" << endl;
		return -1;
	}

	//continue to send data until all of it has been sent or it errors out
	while( totalBytesSent < *lengthOfString) {
		numberOfBytesSent = send(socket, data + totalBytesSent, bytesRemaining, 0);
		if (numberOfBytesSent == -1) {
			cerr << "Debug: Error sending data" << endl;
			break;
		}
		totalBytesSent = numberOfBytesSent + totalBytesSent;
		bytesRemaining = bytesRemaining - numberOfBytesSent;
	}

	if (*lengthOfString != totalBytesSent) {
		cerr << "Debug: Not all data bytes sent" << endl;
	}

	//returns -1 when if it failed within loop
	return numberOfBytesSent;
}

/*
 * Make sure that all of the data is being received from the wire
 */
string recvAll(int socket) {
	int sizeOfRecvString;
	if (recv(socket,&sizeOfRecvString, sizeof(int), 0) < 0) {
		cerr << "Debug: Error recieving string length" << endl;
	}
	sizeOfRecvString = ntohs(sizeOfRecvString);

	char data[sizeOfRecvString+1];
	int totalBytesRecv = 0;
	int bytesRemaining = sizeOfRecvString;
	int numberOfBytesRecv;

	while (totalBytesRecv < sizeOfRecvString) {
		numberOfBytesRecv = recv(socket, data+totalBytesRecv, bytesRemaining, 0);
		if (numberOfBytesRecv == -1) {
			cerr << "Debug: Error receiving data" << endl;
			break;
		}
		totalBytesRecv = numberOfBytesRecv + totalBytesRecv;
		bytesRemaining = bytesRemaining - numberOfBytesRecv;
	}

	if (sizeOfRecvString != totalBytesRecv) {
		cerr << "Debug: Not all data bytes received" << endl;
	}

	data[sizeOfRecvString] = '\0';
	//cout << "Debug: size of string: " << sizeOfRecvString << endl;
	//cout << "Debug: string received: " << data << endl;

	string returnString = data;
	return returnString;
}

/*
 * Receive a string from a socket and return it
 * (to be used in recvURL and recvChainfile
 */
string recvString(int socket) {
	return recvAll(socket);
}

/*
 * Send a URL string to a socket
 */
void sendURL(const string &URL, int socket) {
	sendString(URL, socket);
}

/*
 * Receive a URL string from a socket and return it
 */
string recvURL(int socket) {
	return recvAll(socket);
}


/*
 * main function for the myresolver
 */
void myresolver(string URL, string recordType){
    populateRootServers();
    for (unsigned int i = 0; i < IPv4RootServers.size(); i++){
        cout << IPv4RootServers.at(i) << endl;
    }
    
    for (unsigned int i = 0; i < IPv6RootServers.size(); i++){
        cout << IPv6RootServers.at(i) << endl;
    }
}

#endif /* MYRESOLVER_H_ */
