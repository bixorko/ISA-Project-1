#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <list>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <string>
#include <iostream>
#include <pcap.h>
#include <stdlib.h> 
#include <arpa/inet.h>  
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>	
#include <time.h>
#include <sys/time.h>

using namespace std;
 
void printHelp()
{
    printf("-----------------------------------------------------------------------------\n");
    printf("--                                  HELP                                   --\n");
    printf("-----------------------------------------------------------------------------\n");
    printf("Run sniffer with argument [-i interface] for listening on specific interface.\n \
            \t* To show all available interfaces run sniffer only with -i argument.\n \
            Run sniffer with argument [-r filename] for show network traffic from file.\n \
            \t* File must be in .pcapng format. Otherwise will program exit with warning message.\n");
}

int printInterfaces()
{
    pcap_if_t *interfaces, *device;

	char error[PCAP_ERRBUF_SIZE];
	
	if (pcap_findalldevs(&interfaces, error))
	{
		perror("FAIL during searching for Interfaces!");
        return -1;
	}
	
    printf("Available Interfaces:\n");
    printf("---------------------\n");
    while(interfaces->next != NULL){
        printf("* %s\n" , interfaces->name);
        interfaces = interfaces->next;
    }

    return 0;
}

int calculateHeaderSize(const u_char *data, struct iphdr *iph)
{
    int iphdrlen;
    iphdrlen = iph->ihl*4;
	struct tcphdr *tcph = (struct tcphdr*)(data + iphdrlen + sizeof(struct ethhdr));	
	int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
    
    return header_size;
}

int convertHexLengthBytes(const u_char *data, int j)
{
	char buffer[5];
	sprintf (buffer, "%.2x%.2x", data[j+3], data[j+4]);
	auto val = strtol(buffer, NULL, 16);
	return val;
}

int convertHexLengthSession(const u_char *data, int j)
{
	char buffer[5];
	sprintf (buffer, "%.2x%", data[j]);
	auto val = strtol(buffer, NULL, 16);
	return val;
}

int convertHexLengthCipher(const u_char *data, int j)
{
	char buffer[5];
	sprintf (buffer, "%.2x%.2x", data[j], data[j+1]);
	auto val = strtol(buffer, NULL, 16);
	return val;
}

int convertHexLengthMethods(const u_char *data, int j)
{
	return convertHexLengthSession(data, j);
}

int convertHexLengthServer(const u_char *data, int j)
{
	return convertHexLengthCipher(data, j);
}

int convertHexPort(const u_char *data, int j)
{
	return convertHexLengthCipher(data, j);
}

string calculateSNI(const u_char *data, int header_size)
{
	int length = 1;
	length += convertHexLengthSession(data, header_size);
	length += convertHexLengthCipher(data, length+header_size);
	length += 2;
	length += convertHexLengthMethods(data, header_size+length);
	length += 1;
	length += 2;
	length += 2;
	length += 2;
	length += 2;
	length += 1;
	int nameLength = convertHexLengthCipher(data, header_size+length); 
	length += 2;

	char toAdd[1];
	string sni;
	for (int i = 0; i < nameLength; i++){
		sprintf(toAdd, "%c", data[header_size+length+i]);
		sni += toAdd[0];
	}

	return sni;
}

void fillIpsAndPorts(const u_char *data, string *ipSrc, string *ipDest, string *portSrc, string *portDst)
{
	*ipSrc = std::to_string(data[26]) + "." + std::to_string(data[27]) + "." + std::to_string(data[28]) + "." + std::to_string(data[29]);
	*ipDest = std::to_string(data[30]) + "." + std::to_string(data[31]) + "." + std::to_string(data[32]) + "." + std::to_string(data[33]);
	int portSource = convertHexPort(data, 34);
	*portSrc = std::to_string(portSource);
    int portDestination = convertHexPort(data, 36);
    *portDst = std::to_string(portDestination);
}

void printPacket(int *bytes, int *packets, string *sni, string *ipSrc, string *ipDest, string *portSrc, long long startedAt, long long endedAt, int dateSeconds, int miliSeconds)
{
    char Date[11];
	time_t ts = dateSeconds; 
	struct tm* local = localtime(&ts);
    strftime(Date, sizeof Date, "%Y-%m-%d", local);

    printf("%s %02d:%02d:%02d.%06d,", Date, local->tm_hour, local->tm_min, local->tm_sec, miliSeconds);
    printf("%s,%s,%s,%s,%d,%d,%.3f\n", ipSrc->c_str(), portSrc->c_str(), ipDest->c_str(), sni->c_str(), *bytes, *packets, float((endedAt - startedAt))/1000);
}

struct Packet
{ 
    long long startedAt;
    int wasServerFIN = 0;
    string sniRet;
    int packets = 0;
    int bytes = 0;
    int dateSeconds;
    int miliSeconds;
    string ipSrc, ipDest, portSrc, portDst;
};  

void loadFile(string fileName, int *bytes, int *packets, string *sni, string *ipSrc, string *ipDest, string *portSrc, string *portDst)
{
    char error[PCAP_ERRBUF_SIZE];
    pcap_t * pcap = pcap_open_offline(fileName.c_str(), error);
    pcap_pkthdr *header;
    const u_char *data;

    list<Packet> Packets;
 
    while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0){
        struct iphdr *iph = (struct iphdr *)(data  + sizeof(struct ethhdr));
        int header_size = calculateHeaderSize(data, iph);

        bool packetAdd = true;
        fillIpsAndPorts(data, ipSrc, ipDest, portSrc, portDst);

        if (iph->protocol == 6){
            if(    (data[header_size] == 0x16 || data[header_size] == 0x17 || data[header_size] == 0x14 || data[header_size] == 0x15) \
                && (data[header_size+1] == 0x03) \
                && (data[header_size+2] == 0x00 || data[header_size+2] == 0x01 || data[header_size+2] == 0x02 || data[header_size+2] == 0x03 || data[header_size+2] == 0x04)
            ){ 
				if(data[header_size] == 0x16 && data[header_size+5] == 0x01){
                        Packet packet;
                        packet.sniRet = calculateSNI(data, header_size+43).c_str(); //skip to session ID Length
                        fillIpsAndPorts(data, ipSrc, ipDest, portSrc, portDst);
                        packet.ipSrc = *ipSrc;
                        packet.ipDest = *ipDest;
                        packet.portSrc = *portSrc;
                        packet.portDst = *portDst;  
                        packet.startedAt = ((header->ts.tv_sec) * 1000 + header->ts.tv_usec/1000.0);                    
                        packet.dateSeconds = header->ts.tv_sec;
                        packet.miliSeconds = header->ts.tv_usec;
                        Packets.push_back(packet);
				}

                for (auto it = Packets.begin(); it != Packets.end(); it++){
                    if (((strcmp(ipSrc->c_str(), it->ipSrc.c_str()) == 0 || \
                        strcmp(ipSrc->c_str(), it->ipDest.c_str()) == 0) && \
                        (strcmp(ipDest->c_str(), it->ipDest.c_str()) == 0 || \
                        strcmp(ipDest->c_str(), it->ipSrc.c_str()) == 0)) && \
                        \
                        ((strcmp(portSrc->c_str(), it->portSrc.c_str()) == 0 || \
                        strcmp(portSrc->c_str(), it->portDst.c_str()) == 0) && \
                        (strcmp(portDst->c_str(), it->portDst.c_str()) == 0 || \
                        strcmp(portDst->c_str(), it->portSrc.c_str()) == 0)))
                    {
                        it->bytes += convertHexLengthBytes(data, header_size);
                        it->packets++;
                    }
                }

				for (int j = header_size+5; j < header->caplen; j++){
                    if(    (data[j] == 0x16 || data[j] == 0x17 || data[j] == 0x14 || data[j] == 0x15) \
                		&& (data[j+1] == 0x03) \
                		&& (data[j+2] == 0x00 || data[j+2] == 0x01 || data[j+2] == 0x02 || data[j+2] == 0x03 || data[j+2] == 0x04)
            		){
                        for (auto it = Packets.begin(); it != Packets.end(); it++){
                            if (((strcmp(ipSrc->c_str(), it->ipSrc.c_str()) == 0 || \
                                strcmp(ipSrc->c_str(), it->ipDest.c_str()) == 0) && \
                                (strcmp(ipDest->c_str(), it->ipDest.c_str()) == 0 || \
                                strcmp(ipDest->c_str(), it->ipSrc.c_str()) == 0)) && \
                                \
                                ((strcmp(portSrc->c_str(), it->portSrc.c_str()) == 0 || \
                                strcmp(portSrc->c_str(), it->portDst.c_str()) == 0) && \
                                (strcmp(portDst->c_str(), it->portDst.c_str()) == 0 || \
                                strcmp(portDst->c_str(), it->portSrc.c_str()) == 0)))
                            {
                                it->bytes += convertHexLengthBytes(data, j);
                            }
                        }
					}
                }
            }
            else{
                for (int i = header_size; i < header->caplen; i++){
                    if(    (data[i] == 0x16 || data[i] == 0x17 || data[i] == 0x14 || data[i] == 0x15) \
                        && (data[i+1] == 0x03) \
                        && (data[i+2] == 0x00 || data[i+2] == 0x01 || data[i+2] == 0x02 || data[i+2] == 0x03 || data[i+2] == 0x04)
                    ){
                        for (auto it = Packets.begin(); it != Packets.end(); it++){
                            if (((strcmp(ipSrc->c_str(), it->ipSrc.c_str()) == 0 || \
                                strcmp(ipSrc->c_str(), it->ipDest.c_str()) == 0) && \
                                (strcmp(ipDest->c_str(), it->ipDest.c_str()) == 0 || \
                                strcmp(ipDest->c_str(), it->ipSrc.c_str()) == 0)) && \
                                \
                                ((strcmp(portSrc->c_str(), it->portSrc.c_str()) == 0 || \
                                strcmp(portSrc->c_str(), it->portDst.c_str()) == 0) && \
                                (strcmp(portDst->c_str(), it->portDst.c_str()) == 0 || \
                                strcmp(portDst->c_str(), it->portSrc.c_str()) == 0)))
                            {
                                it->bytes += convertHexLengthBytes(data, i);
                            }
                        }
	
						if (packetAdd){
                            for (auto it = Packets.begin(); it != Packets.end(); it++){
                                if (((strcmp(ipSrc->c_str(), it->ipSrc.c_str()) == 0 || \
                                    strcmp(ipSrc->c_str(), it->ipDest.c_str()) == 0) && \
                                    (strcmp(ipDest->c_str(), it->ipDest.c_str()) == 0 || \
                                    strcmp(ipDest->c_str(), it->ipSrc.c_str()) == 0)) && \
                                    \
                                    ((strcmp(portSrc->c_str(), it->portSrc.c_str()) == 0 || \
                                    strcmp(portSrc->c_str(), it->portDst.c_str()) == 0) && \
                                    (strcmp(portDst->c_str(), it->portDst.c_str()) == 0 || \
                                    strcmp(portDst->c_str(), it->portSrc.c_str()) == 0)))
                                {
                                    it->packets++;
                                }
                            }       
							packetAdd = false;
						}
                    }
                }
            }

            if(data[47] == 0x19 || data[47] == 0x11){
                for (auto it = Packets.begin(); it != Packets.end(); it++){

                    if (((strcmp(ipSrc->c_str(), it->ipSrc.c_str()) == 0 || \
                        strcmp(ipSrc->c_str(), it->ipDest.c_str()) == 0) && \
                        (strcmp(ipDest->c_str(), it->ipDest.c_str()) == 0 || \
                        strcmp(ipDest->c_str(), it->ipSrc.c_str()) == 0)) && \
                        \
                        ((strcmp(portSrc->c_str(), it->portSrc.c_str()) == 0 || \
                        strcmp(portSrc->c_str(), it->portDst.c_str()) == 0) && \
                        (strcmp(portDst->c_str(), it->portDst.c_str()) == 0 || \
                        strcmp(portDst->c_str(), it->portSrc.c_str()) == 0)))
                    {
                        it->wasServerFIN++;
                        if (it->wasServerFIN == 2){
                            printPacket(&it->bytes, &it->packets, &it->sniRet, &it->ipSrc, &it->ipDest, &it->portSrc, it->startedAt, \
                                        ((header->ts.tv_sec) * 1000 + header->ts.tv_usec/1000.0), it->dateSeconds, it->miliSeconds);
                        }
                    }
                }
        
            }
        }
    }
}

int main(int argc, char *argv[])
{
    int bytes = 0;
    int packets = 0;
	string sni;
	string ipSrc;
	string ipDest;
	string portSrc;
    string portDst;

    if (argc == 2){
        if (!strcmp(argv[1], "-help")){
            printHelp();
            return 0;
        }
        else if (!strcmp(argv[1], "-i")){
            printInterfaces();
        }
        else{
            fprintf(stderr, "BAD INPUT ARGUMENTS! For help run sniffer with argument -help.\n");
            return -1;
        }
    }
    else if (argc == 3){
        if (!strcmp(argv[1], "-i")){
            //todo
            //checkIfInterfaceExists(argv[2])
            //liveSniffer(argv[2]);
            return 0;
        }
        else if (!strcmp(argv[1], "-r")){
            if (access(argv[2], F_OK) != -1) {
                loadFile(argv[2], &bytes, &packets, &sni, &ipSrc, &ipDest, &portSrc, &portDst);
            } 
            else {
                fprintf(stderr, "INPUT FILE DOESN'T EXISTS!\n");
                return -1;
            }
        }
        else {
            fprintf(stderr, "BAD INPUT ARGUMENTS! For help run sniffer with argument -help.\n");
            return -1;
        }
    }
    else {
        fprintf(stderr, "BAD INPUT ARGUMENTS! For help run sniffer with argument -help.\n");
        return -1;
    }

}
