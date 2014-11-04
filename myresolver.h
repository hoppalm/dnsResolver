/*
 * Authors: Rawlin Peters and Michael Hoppal
 * awget.h
 * 9-22-14
 *
 * Header file containing all function implementation for myresolver
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

vector<string> IPv4RootServers;
vector<string> IPv6RootServers;

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
    unsigned char name;
    unsigned short type: 16;
    unsigned short payload: 16;
    unsigned char rcode;
    unsigned char version;
    unsigned short Z : 16;
    unsigned short length : 16;
} Dnssec;

typedef struct{
    unsigned short TYPE: 16;
    unsigned short CLASS: 16;
    int TTL;
    unsigned short RDLENGTH: 16;
} Response;

//This project
int clientSetup(const char * server_IP, const char * port, struct sockaddr_in & serverAddress);
void myresolver(string URL, string recordType);
void populateRootServers(vector<string> &IPv4RootServers, vector<string> &IPv6RootServers);
void populateDNSHeader(Header * header);
void populateDnssecRecord(Dnssec * dnssec);
void populateQuestionPacket(Question * question, int queryType);
string convertNameToDNS(string URL);
void sendRecieveDNSQuery(Header* header, Question * question, string DNSUrl, int socket, struct sockaddr_in serverAddress);
void DNSResolver(string URL, int queryType, vector<string> &rootServers);
string getName(char * position, int offset, char * buffer);
int getCompressionInformation(char * currentPosition);
string getARData(int length, char * startingPoint);
string getAAAARData(int length, char * startingPoint);
string convertIntToString (int number);
int getTTL(char * position);
string getHexFromBinaryString (string bytes);

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

string convertIntToString (int number){
    ostringstream tempString;
    tempString<<number;
    return tempString.str();
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
    else if (URL.substr(0, 8) == "https://") {
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
    //cout<<DNSName <<endl;
    return DNSName;
}

//get offset number for the compression
int getCompressionInformation(char * currentPosition){
    unsigned char * temp;
    int asciiNumbers[2];
    
    temp = (unsigned char *)currentPosition;
    asciiNumbers[0] = (  int)(*temp);
    //cout << asciiNumbers[0] << endl;
    
    currentPosition = currentPosition + 1;
    temp = (unsigned char *)currentPosition;
    asciiNumbers[1] = ( int)(*temp);
    
    //cout <<asciiNumbers[1] << endl;
    currentPosition = currentPosition + 1;
    
    bitset<8> bytes1 (asciiNumbers[0]);
    
    //cout << "Debug first 8 bytes for offset " << bytes1 << endl;
    
    bitset<8> bytes2 (asciiNumbers[1]);
    
    //cout << "Debug last 8 bytes for offset "<< bytes2 << endl;
    
    if ( bytes1[7] != 1 || bytes1[6] != 1) {
        return -1;
    }
    
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

string getName(char * position, int offset, char * buffer){
    
    string name = "";
    position = position + offset;
    int firstIteration = 0;
    
    int testCompression = getCompressionInformation(position);
    if (testCompression > 0){
        position = &buffer[0];
        position = position + testCompression;
    }
    
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
        
        int testCompression = getCompressionInformation(position);
        if (testCompression > 0){
            position = &buffer[0];
            position = position + testCompression;
        }
        
        temp = (unsigned char *) position;
        
        numberOfBytesToAdvance = (int)*temp;
        //cout << "Debug: Number of bytes to advance " << numberOfBytesToAdvance << endl;
        
        position = position + 1;
        firstIteration++;
    }
    //cout << "Debug: Name returned " << name << endl;
    return name;
}

string getARData(int length, char * startingPoint){
    string rData = "";
    for (int i = 0; i < length; i++) {
        unsigned char * temp;
        temp = (unsigned char *) startingPoint;
        
        int part = (int)*temp;
        
        rData.append(convertIntToString(part));
        
        if ((i+1) < length) {
            rData.append(1,'.');
        }
        startingPoint += 1;
        
    }
    return rData;
}

string getAAAARData(int length, char * startingPoint){
    string rData;
    string previous = "";
    string byteString = "";
    int part;
    int counter = 0;
    unsigned char * temp;
    
    for (int i = 0; i < length/2; i++) {
        string tempString = "";
        
        temp = (unsigned char *) startingPoint;
        
        part = (int)*temp;
        
        bitset<8> bits (part);
        
        byteString = bits.to_string();
        
        tempString.append(getHexFromBinaryString(byteString));
        
        startingPoint += 1;
        
        temp = (unsigned char *) startingPoint;
        
        part = (int)*temp;
        
        bitset<8> bits1 (part);
        
        byteString = bits1.to_string();
        
        tempString.append(getHexFromBinaryString(byteString));
        
        startingPoint += 1;
        if (tempString.length() > 1 && tempString.at(0) == '0'){
            tempString = tempString.substr(1);
        }
        rData.append(tempString);
        
        if (previous == "" && counter == 0){
            rData.append(1,':');
            counter++;
        }
        else if (previous != "" && (i+1) < length/2){
            rData.append(1,':');
            counter = 0;
        }
        
        previous = tempString;
        
    }
    return rData;
}

void DNSResolver(string URL, int queryType, vector<string> &rootServers){
    
    int currentServerID = 0;
    bool loop = true;
    
    Header header;
    Question question;
    populateDNSHeader(&header);
    
    while (loop) {
        
        string currentIP = rootServers.at(currentServerID);
        
        struct sockaddr_in serverAddress;
        int socket = clientSetup(currentIP.c_str(), "53", serverAddress);
        
        populateQuestionPacket(&question, queryType);
        
        string DNSUrl = convertNameToDNS(URL);
        
        //store the ips
        vector<string> nextIPs;
        vector<string> cnames;
        vector<string> answerIPs;
        char * currentPosition;
        char * offsetPosition;
        
        unsigned int sizeOfStruct = sizeof(serverAddress);
        char buffer [65536];
        const char * queryName = DNSUrl.c_str();
        
        memcpy(buffer, &header, sizeof(Header));
        memcpy(buffer+sizeof(Header), queryName, strlen(queryName)+1);
        memcpy(buffer+sizeof(Header)+strlen(queryName)+1, &question, sizeof(Question));
        
        //cout << "Debug: sending Packet" << endl;
        
        if( sendto(socket,(char*)buffer,sizeof(Header) + strlen(queryName)+1 + sizeof(Question),0,(struct sockaddr*)&serverAddress,sizeOfStruct) < 0)
        {
            cout << "Debug: sending query failed" << endl;
            exit(1);
        }
        
        //cout << "Debug: send complete" << endl;
        
        //cout << "Debug: Receiving Packet" << endl;
        
        if(recvfrom (socket,(char*)buffer,65536,0,(struct sockaddr*)&serverAddress,&sizeOfStruct) < 0)
        {
            cout << "Debug: receive query failed" << endl;
            exit(1);
        }
        
        //cout << "Debug: Received Packet" << endl;
        
        Header * responseHeader = (Header *)buffer;
        
        //truncated error out
        if (responseHeader->tc == 1) {
            cerr << "Error truncated bit was set in response header" << endl;
            //TO DO handle situation
        }
        char rcode = responseHeader->rcode;
        if (rcode == 2 && rcode == 4 && rcode == 5){
            currentServerID++;
            continue;
            
        }
        else if(rcode == 3){
            cerr << "Domain name does not exist, quitting" << endl;
            exit(1);
        }
        
        currentPosition = &buffer[sizeof(Header) + strlen(queryName)+1 + sizeof(Question)];
        
        int numberOfAnswers = ntohs(responseHeader->ancount);
        
        //cout << numberOfAnswers << endl;
        
        //loop though answers store in the answers vectors
        cout << "-----------------ANSWERS-------------------" << endl;
        
        for(int i = 0; i < numberOfAnswers; i++){
            cout << endl;
            
            int offset = getCompressionInformation(currentPosition);
            currentPosition +=2;
            string name = "";
            offsetPosition = &buffer[0];
            name = getName(offsetPosition, offset, buffer);
            Response * response = (Response *)currentPosition;
            response->TTL = getTTL(currentPosition);
            currentPosition = currentPosition + 10;
            
            cout << "Name: " << name << endl;
            cout << "Type: " << ntohs(response->TYPE) << endl;
            cout << "CLASS: " << ntohs(response->CLASS) << endl;
            cout << "TTL: " << response->TTL << endl;
            cout << "RDLENGTH: " << ntohs(response->RDLENGTH) << endl;
            
            
            int type = ntohs(response->TYPE);
            
            int length = ntohs(response->RDLENGTH);
            
            string cname = "";
            string answerIP = "";
            
            if (type == 5){
                cname = getName(currentPosition,0,buffer);
                cnames.push_back(cname);
            }
            
            if(queryType == 1) {
                //a record
                if (type == 1){
                    answerIP = getARData(length, currentPosition);
                    answerIPs.push_back(answerIP);
                }
            }
            else {
                //aaaa record
                if (type == 28){
                    answerIP = getAAAARData(length, currentPosition);
                    answerIPs.push_back(answerIP);
                }
            }
            
            currentPosition = currentPosition + length;
            cout << "Cname: " << cname<< endl;
            cout << "answerIP: " << answerIP<< endl;

            
            cout << endl;
        }
        
        cout << "----------------------------------------------" << endl;
        
        int numberOfAuthorities = ntohs(responseHeader->nscount);
        
        //loop through authorities "dont need to process anything"
        cout << "-----------------AUTHORITES-------------------" << endl;
        for(int i = 0; i < numberOfAuthorities; i++){
            cout << endl;
            int offset = getCompressionInformation(currentPosition);
            currentPosition +=2;
            string name = "";
            offsetPosition = &buffer[0];
            name = getName(offsetPosition, offset, buffer);
            Response * response = (Response *)currentPosition;
            response->TTL = getTTL(currentPosition);
            currentPosition = currentPosition + 10;
            
            cout << "Name: " << name << endl;
            cout << "Type: " << ntohs(response->TYPE) << endl;
            cout << "CLASS: " << ntohs(response->CLASS) << endl;
            cout << "TTL: " << response->TTL << endl;
            cout << "RDLENGTH: " << ntohs(response->RDLENGTH) << endl;
            
            int type = ntohs(response->TYPE);
            
            int length =ntohs(response->RDLENGTH);
            
            string rData;
            
            if (type == 2){
                rData = getName(currentPosition,0,buffer);
            }
            
            currentPosition = currentPosition + length;
            cout << "Rdata: " << rData << endl;
            
            cout << endl;
        }
        cout << "----------------------------------------------" << endl;
        
        
        int numberOfAdditional = ntohs(responseHeader->arcount);
        
        cout << "-----------------ADDITIONAL-------------------" << endl;
        //loop through additionals store ips
        for(int i = 0; i < numberOfAdditional; i++){
            cout << endl;
            
            int offset = getCompressionInformation(currentPosition);
            cout << offset << endl;
            currentPosition +=2;
            string name = "";
            offsetPosition = &buffer[0];
            name = getName(offsetPosition, offset, buffer);
            Response * response = (Response *)currentPosition;
            response->TTL = getTTL(currentPosition);
            currentPosition = currentPosition + 10;
            cout << "Name: " << name << endl;
            cout << "Type: " << ntohs(response->TYPE) << endl;
            cout << "CLASS: " << ntohs(response->CLASS) << endl;
            cout << "TTL: " << response->TTL << endl;
            cout << "RDLENGTH: " << ntohs(response->RDLENGTH) << endl;
            
            int type = ntohs(response->TYPE);
            int length =ntohs(response->RDLENGTH);
            string rData;
            

            //a record
            if (type == 1){
                rData = getARData(length, currentPosition);
                nextIPs.push_back(rData);
            }
            //aaaa record
            if (type == 28){
                rData = getAAAARData(length, currentPosition);
            }

            
            currentPosition = currentPosition + length;
            cout << "Rdata: " << rData << endl;
            
            cout << endl;
        }
        
        cout << "------------------------------------" << endl;
        
        if (numberOfAnswers == 0 && nextIPs.size() > 0){
            DNSResolver(URL, queryType, nextIPs);
            return;
        }
        
        if (numberOfAnswers == 0 && nextIPs.size() == 0){
            currentServerID++;
        }
        
        if (numberOfAnswers > 0){
            if (cnames.size() > 0 && answerIPs.size() == 0){
                DNSResolver(cnames.at(0), queryType, IPv4RootServers);
            }
            return;
        }
        
        cout << "No Answers" << endl;
        exit(1);
    }
}

int getTTL(char * position){
    position = position + 4;
    bitset<32> comparebytes(string("11111111111111111111111111111111"));
    int index = 31;
    for (int i = 0; i < 4; i++){
        unsigned char * temp;
        temp = (unsigned char *)position;
        int asciiNumber = (int)(*temp);
        position = position + 1;
        bitset<8> bytes (asciiNumber);
        //cout << bytes << endl;
        for (int i = 7; i >= 0; i--){
            comparebytes[index] = comparebytes[index] & bytes[i];
            //cout << bytes[i] << endl;
            index--;
        }
    }
    //cout << "Debug all 32 bytes for offset " << comparebytes << endl;
    
    int TTL = comparebytes.to_ulong();
    
    return TTL;
}

string getHexFromBinaryString (string bytes)
{
    string hexReturn = "";
    
    for (int i = 0; i < 2; i++)
    {
        string binaryValue = bytes.substr(0,4);
        if (binaryValue == "0000") hexReturn.append(1,'0');
        if (binaryValue == "0001") hexReturn.append(1,'1');
        if (binaryValue == "0010") hexReturn.append(1,'2');
        if (binaryValue == "0011") hexReturn.append(1,'3');
        if (binaryValue == "0100") hexReturn.append(1,'4');
        if (binaryValue == "0101") hexReturn.append(1,'5');
        if (binaryValue == "0110") hexReturn.append(1,'6');
        if (binaryValue == "0111") hexReturn.append(1,'7');
        if (binaryValue == "1000") hexReturn.append(1,'8');
        if (binaryValue == "1001") hexReturn.append(1,'9');
        if (binaryValue == "1010") hexReturn.append(1,'a');
        if (binaryValue == "1011") hexReturn.append(1,'b');
        if (binaryValue == "1100") hexReturn.append(1,'c');
        if (binaryValue == "1101") hexReturn.append(1,'d');
        if (binaryValue == "1110") hexReturn.append(1,'e');
        if (binaryValue == "1111") hexReturn.append(1,'f');
        bytes = bytes.substr(4);
    }
    if (hexReturn == "00"){
        return "";
    }
    return hexReturn;
}

/*
 * main function for myresolver
 */
void myresolver(string URL, int recordType){

    populateRootServers(IPv4RootServers, IPv6RootServers);
    
    /*cout << "Debug: IPv4RootServers  ";
    for (unsigned int i = 0; i < IPv4RootServers.size(); i++){
        cout << IPv4RootServers.at(i) << " ";
    }
    cout<< endl;
    
    cout << "Debug: IPv6RootServers ";
    for (unsigned int i = 0; i < IPv6RootServers.size(); i++){
        cout << IPv6RootServers.at(i) << " ";
    }
    cout<< endl;
    */
    
    DNSResolver(URL, recordType, IPv4RootServers);
    /*
    if(recordType == 1) {
        DNSResolver(URL, recordType, IPv4RootServers);
    }
    else {
        DNSResolver(URL, recordType, IPv6RootServers);
    }*/
}

#endif /* MYRESOLVER_H_ */
