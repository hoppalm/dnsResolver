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
#include <bitset>

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
using std::bitset;

#define BUFFERSIZE 512

//Header Struct
typedef struct{
    unsigned int id : 16; /*A 16 bit identifier assigned by the program that generates any kind of query*/
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
    unsigned int qbcount: 16; /*an unsigned 16 bit integer specifying the number of entries in the question section*/
    unsigned int ancount: 16; /*an unsigned 16 bit integer specifying the number of resource records in the answer section*/
    unsigned int nscount: 16; /*an unsigned 16 bit integer specifying the number of name server resource records in the
                               authority records section*/
    unsigned int arcount: 16; /*an unsigned 16 bit integer specifying the number of resource records in the additional
                               records section*/
} Header;

typedef struct{
    unsigned int QTYPE: 16;
    unsigned int QCLASS: 16;
} Question;

typedef struct{
    short TYPE: 16;
    short CLASS: 16;
    int TTL;
    short RDLENGTH: 16;
} Response;

//This project
int clientSetup(const char * server_IP, const char * port, struct sockaddr_in & serverAddress);
void myresolver(string URL, string recordType);
void populateRootServers(vector<string> &IPv4RootServers, vector<string> &IPv6RootServers);
void populateDNSHeader();
void populateQuestionPacket(Question * question, int queryType);
string convertNameToDNS(string URL);
void sendRecieveDNSQuery(Header* header, Question * question, string DNSUrl, int socket, struct sockaddr_in serverAddress);
void DNSResolver(string URL, int queryType, vector<string> &rootServers);
string getName(char * position, int offset);
int getCompressionInformation(char * currentPosition);
string getRData(int length, char * startingPoint);

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
    header->id = htons(getpid());
    header->qr = 0;
    header->opcode = 0;
    header->aa = 0;
    header->tc = 0;
    header->rd = 0;
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
    //cout << "Debug: appending: " << temp << " for " << indexes.at(position) << endl;
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
            //cout << "Debug: appending: " << temp << " for " << (number-1) << endl;
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
    //store the answers
    vector<Response> answersStruct;
    vector<string> answerNames;
    vector<string> answerRData;
    vector<string> nextIPs;
    char * currentPosition;
    char * offsetPosition;
    
    unsigned int sizeOfStruct = sizeof(serverAddress);
    char buffer [65536];
    const char * queryName = DNSUrl.c_str();
    
    memcpy(buffer, &header, sizeof(Header));
    memcpy(buffer+sizeof(Header), queryName, strlen(queryName)+1);
    memcpy(buffer+sizeof(Header)+strlen(queryName)+1, &question, sizeof(Question));
    
    cout << "Debug: sending Packet" << endl;
    
    if( sendto(socket,(char*)buffer,sizeof(Header) + strlen(queryName)+1 + sizeof(Question),0,(struct sockaddr*)&serverAddress,sizeOfStruct) < 0)
    {
        cout << "Debug: sending query failed" << endl;
        exit(1);
    }
    
    cout << "Debug: send complete" << endl;
    
    cout << "Debug: Receiving Packet" << endl;
    
    if(recvfrom (socket,(char*)buffer,65536,0,(struct sockaddr*)&serverAddress,&sizeOfStruct) < 0)
    {
        cout << "Debug: receive query failed" << endl;
        exit(1);
    }
    
    cout << "Debug: Received Packet" << endl;
    
    Header * responseHeader = (Header *)buffer;
    
    //truncated error out
    if (responseHeader->tc == 1) {
        cerr << "Error truncated bit was set in response header" << endl;
        //TO DO handle situation
    }
    char rcode = responseHeader->rcode;
    //error condition. TODO: Handle each one appropriately
    if (rcode == 2 && rcode == 4 && rcode == 5){
        //TODO HANDLE go to next server
        //Server failure - The name server was unable to process this query due to a problem with the nameserver.
        //Not Implemented - The name server does not support the requested kind of query.
        //Refused - The name server refuses to perform the specified operation for policy reasons.
    }
    else if(rcode == 3){
        cerr << "Domain name does not exist, quitting" << endl;
        exit(1);
    }
    
    currentPosition = &buffer[sizeof(Header) + strlen(queryName)+1 + sizeof(Question)];
    
    offsetPosition = &buffer[0];
    
    int numberOfAnswers = ntohs(responseHeader->ancount);
    
    //loop though answers store in the answers vectors
    /*
    for(int i = 0; i < numberOfAnswers; i++){
        int offset = getCompressionInformation(currentPosition);
        currentPosition +=2;
        cout << "Debug offset " << offset << endl;
        string name = getName(offsetPosition, offset);
        
    }*/
    
    int numberOfAuthorities = ntohs(responseHeader->nscount);
    
    //loop through authorities "dont need to process anything"
    
    for(int i = 0; i < numberOfAuthorities; i++){
        int offset = getCompressionInformation(currentPosition);
        currentPosition +=2;
        string name = getName(offsetPosition, offset);
        Response * response = (Response *)currentPosition;
        currentPosition = currentPosition + sizeof(Response);
        cout << "------------------------------------" << endl;
        cout << "Name: " << name << endl;
        cout << "Type: " << ntohs(response->TYPE) << endl;
        cout << "CLASS: " << ntohs(response->CLASS) << endl;
        cout << "TTL: " << ntohs(response->TTL) << endl; //giving me wrong answers
        cout << "RDLENGTH: " << ntohs(response->RDLENGTH) << endl;
     
        int length =ntohs(response->RDLENGTH);
        string rData = getRData(length, currentPosition);
        currentPosition = currentPosition + length;
        cout << "Rdata: " << rData << endl;
        cout << "------------------------------------" << endl;
    }
    
    
    
    int numberOfAdditional = ntohs(responseHeader->arcount);
    /*
    //loop through additionals store ips
    for(int i = 0; i < numberOfAdditional; i++){
        int offset = getCompressionInformation(currentPosition);
        currentPosition +=2;
        cout << "Debug offset " << offset << endl;
        string name = getName(offsetPosition, offset);
    }
    */
    
    //print out answers
    
}
/*
typedef struct{
    unsigned int TYPE: 16;
    unsigned int CLASS: 16;
    unsigned int TTL: 32;
    unsigned int RDLENGTH: 16;
} Response;*/

//get offset number for the compression
int getCompressionInformation(char * currentPosition){
    char * temp;
    int asciiNumbers[2];
    
    temp = (char *)currentPosition;
    asciiNumbers[0] = (int)(*temp);
    
    currentPosition = currentPosition + 1;
    temp = (char *)currentPosition;
    asciiNumbers[1] = (int)(*temp);
    currentPosition = currentPosition + 1;
    
    bitset<8> bytes1 (asciiNumbers[0]);
    
    //cout << "Debug first 8 bytes for offset " << bytes1 << endl;
    
    bitset<8> bytes2 (asciiNumbers[1]);
    
    //cout << "Debug last 8 bytes for offset "<< bytes2 << endl;
    
    bitset<16> comparebytes(string("0011111111111111"));
    
    for (int i = 0; i < 15; i++){
        if (i > 7){
            comparebytes[i] = comparebytes[i] & bytes1[i-8];
        }
        else {
            comparebytes[i] = comparebytes[i] & bytes2[i];
        }
    }
    //cout << "Debug all 16 bytes for offset " << comparebytes << endl;
    
    int offset = comparebytes.to_ulong();
    
    return offset;
}

string getName(char * position, int offset){
    string name = "";
    position = position + offset;
    int firstIteration = 0;
    
    unsigned char * temp;
    temp = (unsigned char *) position;
    
    int numberOfBytesToAdvance = (int)*temp;
    //cout << "Debug: Number of bytes to advance " << numberOfBytesToAdvance << endl;
    position = position + 1;
    
    while (numberOfBytesToAdvance != 0){
        if(firstIteration != 0){
            name.append(1,'.');
        }
        for (int i = 0; i<numberOfBytesToAdvance; i++) {
            temp = (unsigned char *) position;
            name.append(1,*temp);
            position = position + 1;
        }
        
        temp = (unsigned char *) position;
        
        numberOfBytesToAdvance = (int)*temp;
        //cout << "Debug: Number of bytes to advance " << numberOfBytesToAdvance << endl;
        position = position + 1;
    }
    //cout << "Debug: Name returned " << name << endl;
    return name;
}

string getRData(int length, char * startingPoint){
    return "";
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
    //cout << "Debug host name : " << DNSName << endl;
    
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
