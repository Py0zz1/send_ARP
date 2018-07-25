all : send_ARP
	
send_ARP : main.o
	g++ -g -std=c++14 -o send_ARP main.o -lpcap -lpthread

main.o : psy_header.h
	g++ -g -c -std=c++14 -o main.o main.cpp

clean :
	rm -f *.o send_ARP

