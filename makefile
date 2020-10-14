CC=g++

pcap: main.o 
	$(CC) -o sniffer main.cc -lpcap