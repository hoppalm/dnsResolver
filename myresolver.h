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
using std::ostringstream;
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

//Header Struct
typedef struct{
    unsigned short id; /*A 16 bit identifier assigned by the program that generates any kind of query*/
    unsigned char rd: 1; /* this bit directs the name server to pursue the query recursively*/
    unsigned char tc: 1; /*specifies that this message was truncated*/
    unsigned char aa: 1; /*Authoritative Answer - this bit is only meaningful in responses, and specifies that the responding
                          name server is an authority for the domain name in question section.*/
    unsigned char opcode: 4; /*A four bit field that specifies kind of query in this message*/
    unsigned char qr: 1; /*A one bit field that specifies whether this message is a query (0), or a response (1).*/
    unsigned char rcode: 4; /*Response code - this 4 bit field is set as part of responses*/
    unsigned char z: 3; /*Reserved for future use.*/
    unsigned char ra: 1; /*this be is set or cleared in a response, and denotes whether recursive
                         query support is available in the name server*/
    unsigned short qbcount: 16; /*an unsigned 16 bit integer specifying the number of entries in the question section*/
    unsigned short ancount: 16; /*an unsigned 16 bit integer specifying the number of resource records in the answer section*/
    unsigned short nscount: 16; /*an unsigned 16 bit integer specifying the number of name server resource records in the
                               authority records section*/
    unsigned short arcount: 16; /*an unsigned 16 bit integer specifying the number of resource records in the additional
                               records section*/
} Header;

typedef struct{
    unsigned int QTYPE: 16;
    unsigned int QCLASS: 16;
} Question;

//This project
int clientSetup(const char * server_IP, const char * port, struct sockaddr_in & serverAddress);
void myresolver(string URL, string recordType);
void populateRootServers(vector<string> &IPv4RootServers, vector<string> &IPv6RootServers);
void populateDNSHeader();
void populateQuestionPacket(Question * question, int queryType);
string convertNameToDNS(string URL);
void sendRecieveDNSQuery(Header* header, Question * question, string DNSUrl, int socket, struct sockaddr_in serverAddress);
void DNSResolver(string URL, int queryType, vector<string> &rootServers);


/*
 * populates the root server vectors
 */
void populateRootServers(vector<string> &IPv4RootServers, vector<string> &IPv6RootServers){
    //ipv4 servers
    IPv4RootServers.push_back("192.5.5.241");
    IPv4RootServers.push_back("192.112.36.4");
    IPv4RootServers.push_back("128.63.2.53");
    IPv4RootServers.push_back("192.36.148.17");
    IPv4RootServers.push_back("192.58.128.30");
    IPv4RootServers.push_back("193.0.14.129");
    IPv4RootServers.push_back("199.7.83.42");
    
    //ipv6 servers
    IPv6RootServers.push_back("2001:500:2f::f");
    IPv6RootServers.push_back("2001:500:1::803f:235");
    IPv6RootServers.push_back("2001:7fe::53");
    IPv6RootServers.push_back("2001:503:c27::2:30");
    IPv6RootServers.push_back("2001:7fd::1");
    IPv6RootServers.push_back("2001:500:3::42");
}

/*
 * UDP create a client socket and connect to a server at the given IP and port number.
 */
int clientSetup(const char * server_IP, const char * port, struct sockaddr_in & serverAddress){
    int clientSocket;
    
    if ( (clientSocket=socket(AF_INET,SOCK_DGRAM,0)) < 0){
        cout << "ERROR creating client socket" << endl;
        exit(1);
    }
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr= inet_addr(server_IP);
    serverAddress.sin_port=htons(53);
    
    return clientSocket;
    
}

/*
 * Populating DNS Header Packet
 */
void populateDNSHeader(Header * header){
    cout << "Debug process id: " << getpid() << endl;
    header->id = htons(getpid());
    header->qr = 0;
    header->opcode = 0;
    header->aa = 0;
    header->tc = 0;
    header->rd = 1;
    header->ra = 0;
    header->z = 0;
    header->rcode = 0;
    header->qbcount = htons(1); // one question
    header->ancount = 0;
    header->nscount = 0;
    header->arcount = 0;
}

void populateQuestionPacket(Question * question, int queryType){
    question->QTYPE = htons(queryType);
    question->QCLASS = htons(1);
}


string convertNameToDNS(string URL){
    
    vector<int> indexes;
    string DNSName;
    char temp;
    
    if (URL.substr(0, 7) == "http://") {
        URL = URL.substr(7);
    }
    else if (DNSName.substr(0, 8) == "https://") {
        URL = URL.substr(8);
    }
    
    int index = URL.find(".");
    
    while (index >= 0){
        indexes.push_back(index);
        index = URL.find(".",index+1);
    }
    
    int position = 0;
    //cout<< indexes.size() << endl;
    if (indexes.size() == 0){
        cerr << "ERROR: URL is invalid please try again" << endl;
        exit(1);
    }
    temp = indexes.at(position);
    cout << "Debug: appending: " << temp << " for " << indexes.at(position) << endl;
    DNSName.append(1,temp);
    position++;
    for (int i = 0; i< URL.length();i++) {
        if (URL.at(i) == '.') {
            int number;
            if (position >= indexes.size()){
                number = URL.length() - indexes.at(position-1);
            }
            else {
                //cout << position << endl;
                number = indexes.at(position) - indexes.at(position-1);
                position++;
            }
            temp = number-1;
            cout << "Debug: appending: " << temp << " for " << (number-1) << endl;
            DNSName.append(1,temp);
        }
        else {
            DNSName.append(1,URL.at(i));
        }
    }
    temp = 0;
    DNSName.append(1,0);
    return DNSName;
}

void sendRecieveDNSQuery(Header header, Question question, string DNSUrl, int socket, struct sockaddr_in serverAddress){
    unsigned int sizeOfStruct = sizeof(serverAddress);
    char buffer [65536];
    const char * queryName = DNSUrl.c_str();
    cout << "DEBUG size of header " << sizeof(Header) << endl;
    cout << "DEBUG size of question " << sizeof(Question) << endl;
    cout << "DEBUG size of name " << strlen(queryName) << endl;
    cout <<queryName << endl;
    
    memcpy(buffer, &header, sizeof(Header));
    memcpy(buffer+sizeof(Header), queryName, strlen(queryName)+1);
    memcpy(buffer+sizeof(Header)+strlen(queryName)+1, &question, sizeof(Question));
    
    cout << "Debug: sending Packet" << endl;
    if( sendto(socket,(char*)buffer,sizeof(Header) + strlen(queryName)+1 + sizeof(Question),0,(struct sockaddr*)&serverAddress,sizeOfStruct) < 0)
    {
        cout << "Debug: sending query failed" << endl;
        exit(1);
    }
    cout << "send complete" << endl;
    
    
    cout << "Debug: Receiving Packet" << endl;
    if(recvfrom (socket,(char*)buffer,65536,0,(struct sockaddr*)&serverAddress,&sizeOfStruct) < 0)
    {
        cout << "Debug: receive query failed" << endl;
        exit(1);
    }
    cout << "Debug: Receiving Packet" << endl;
}



void DNSResolver(string URL, int queryType, vector<string> &rootServers){
    int currentServerID = 0;
    
    Header header;
    Question question;
    populateDNSHeader(&header);
    
    string currentIP = rootServers.at(currentServerID);
    
    struct sockaddr_in serverAddress;
    int dnsSocket = clientSetup(currentIP.c_str(), "53", serverAddress);
    
    populateQuestionPacket(&question, queryType);
    
    string DNSName = convertNameToDNS(URL);
    cout << "Debug host name : " << DNSName << endl;
    
    sendRecieveDNSQuery(header, question, DNSName, dnsSocket, serverAddress);
    

}

/*
 * main function for myresolver
 */
void myresolver(string URL, int recordType){
    vector<string> IPv4RootServers;
    vector<string> IPv6RootServers;
    populateRootServers(IPv4RootServers, IPv6RootServers);

    cout << "Debug: IPv4RootServers  ";
    for (unsigned int i = 0; i < IPv4RootServers.size(); i++){
        cout << IPv4RootServers.at(i) << " ";
    }
    cout<< endl;
    
    cout << "Debug: IPv6RootServers ";
    for (unsigned int i = 0; i < IPv6RootServers.size(); i++){
        cout << IPv6RootServers.at(i) << " ";
    }
    cout<< endl;
    
    if(recordType == 1) {
        DNSResolver(URL, recordType, IPv4RootServers);
    }
    else {
        DNSResolver(URL, recordType, IPv6RootServers);
    }
}

#endif /* MYRESOLVER_H_ */
