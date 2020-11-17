CC=g++

pcap: main.o 
	$(CC) -o sslsniff main.cc -lpcap
