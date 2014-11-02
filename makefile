all:	myresolver

myresolver:	myresolver.h myresolver.cc
		g++ -Wall myresolver.cc -o myresolver
		
clean:
		rm -f myresolver
