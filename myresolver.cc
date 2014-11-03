/*
 * Authors: Rawlin Peters and Michael Hoppal
 * myresolver.cc
 * 11-2-14
 *
 * Main function source file for myresolver
 */

#include <string>
#include "myresolver.h"

int main(int argc, char* argv[]) {
    
	string URL = "";
	string recordType = "";
    int recordID = 1;

	if (argc < 2) {
		cerr << "ERROR: too few arguments" << endl;
		cerr << "USAGE: " << argv[0] << " <URL> [RRTYPE]" << endl;
		exit(1);
	}
    if (argc == 2) {
		URL = string(argv[1]);
	}
	else if (argc == 3) {
        URL = string(argv[1]);
        recordType = argv[2];
        if (recordType.compare("AAAA") == 0 || recordType.compare("aaaa") == 0){
            recordID = 28;
        }
        else if(recordType.compare("A") == 0 || recordType.compare("a") == 0) {
            recordID = 1;
        }
        else {
            cerr << "RRTYPE given must be AAAA or A please try again" << endl;
            exit(1);
        }
	}
	else {
		cerr << "ERROR: too many arguments" << endl;
		cerr << "USAGE: " << argv[0] << " <URL> [RRTYPE]" << endl;
		exit(1);
	}

	myresolver(URL, recordID);

	return 0;
}
