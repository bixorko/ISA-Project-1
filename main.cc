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
    if (iph->version == 6){
        iphdrlen = 40;
    }
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
    if (data[header_size+length] != 0x00){
        length += 4;
    }
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

    if (strcmp(sni.c_str(),"\n") == 0){
        return "";
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

string convertIPv6(const u_char *data, int offset)
{
    char buffer[64];
	sprintf (buffer, "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x", data[offset+1], data[offset+2],
    data[offset+3],data[offset+4],data[offset+5],data[offset+6],data[offset+7],data[offset+8],data[offset+9],data[offset+10],data[offset+11],data[offset+12],
    data[offset+13],data[offset+14], data[offset+15], data[offset+16]);

    char *ip6str = buffer;
    struct in6_addr result;
    char toReturn[64];

    inet_pton(AF_INET6, ip6str, &result);
    inet_ntop(AF_INET6, &(result), toReturn, 64);
    return toReturn;
}

void fillIpsAndPorts6(const u_char *data, string *ipSrc, string *ipDest, string *portSrc, string *portDst)
{
    *ipSrc = convertIPv6(data, 21);
    *ipDest = convertIPv6(data, 37);
	int portSource = convertHexPort(data, 54);
	*portSrc = std::to_string(portSource);
    int portDestination = convertHexPort(data, 56);
    *portDst = std::to_string(portDestination);
}

void printPacket(int *bytes, int *packets, string *sni, string *ipSrc, string *ipDest, string *portSrc, int dateSeconds, int miliSeconds, struct timeval startTime, struct timeval endTime)
{
    char Date[11];
	time_t ts = dateSeconds; 
	struct tm* local = localtime(&ts);
    strftime(Date, sizeof Date, "%Y-%m-%d", local);

    printf("%s %02d:%02d:%02d.%06d,", Date, local->tm_hour, local->tm_min, local->tm_sec, miliSeconds);

    struct timeval duration;
    duration.tv_sec = endTime.tv_sec - startTime.tv_sec;
    duration.tv_usec = endTime.tv_usec - startTime.tv_usec;

    while(duration.tv_usec<0){
        duration.tv_sec -= 1;
        duration.tv_usec += 1000000;
    }
    printf("%s,%s,%s,%s,%d,%d,%ld.%06lu\n", ipSrc->c_str(), portSrc->c_str(), ipDest->c_str(), sni->c_str(), *bytes, *packets, duration.tv_sec, (unsigned long)duration.tv_usec);

}

struct Packet
{ 
    struct timeval startTime;
    int wasServerFIN = 0;
    string sniRet;
    int packets = 0;
    int bytes = 0;
    int dateSeconds;
    int miliSeconds;
    string ipSrc, ipDest, portSrc, portDst;
    bool wasHello = false;
    bool isPrintable = false; //set to true if client hello and server hello arrived (they also must arrived -> first client then server)
    string whoFINip;
    string whoFINport;
    bool isSameIP = false;
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
        int offset = header_size;

        if (iph->version == 6){
            fillIpsAndPorts6(data, ipSrc, ipDest, portSrc, portDst);
        }
        else{
            fillIpsAndPorts(data, ipSrc, ipDest, portSrc, portDst);
        }

        int controlTCP = iph->protocol;

        if (iph->version == 6 && data[20] == 0x06){
            controlTCP = 6;
        }

        if (controlTCP){
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
                    packetAdd = false;
                }
            }

            if (packetAdd || Packets.empty()){
                Packet packet;
                packet.ipSrc = *ipSrc;
                packet.ipDest = *ipDest;
                packet.portSrc = *portSrc;
                packet.portDst = *portDst;  

                if (strcmp(ipSrc->c_str(), ipDest->c_str()) == 0){
                    packet.isSameIP = true;
                }
                packet.packets = 1;                  
                packet.dateSeconds = header->ts.tv_sec;
                packet.miliSeconds = header->ts.tv_usec;
                packet.startTime.tv_sec = header->ts.tv_sec;
                packet.startTime.tv_usec = header->ts.tv_usec;
                Packets.push_back(packet);
            }

            if(    (data[header_size] == 0x16 || data[header_size] == 0x17 || data[header_size] == 0x14 || data[header_size] == 0x15) \
                && (data[header_size+1] == 0x03) \
                && (data[header_size+2] == 0x01 || data[header_size+2] == 0x02 || data[header_size+2] == 0x03 || data[header_size+2] == 0x04)
            ){ 
				if(data[header_size] == 0x16 && data[header_size+5] == 0x01){
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
                            it->wasHello = true;
                            it->sniRet = calculateSNI(data, header_size+43).c_str(); //skip to session ID Length
                        }
                    }
				}

                if(data[header_size] == 0x16 && data[header_size+5] == 0x02){
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
                            if (it->wasHello){
                                it->isPrintable = true;
                            }
                        }
                    }
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
                        offset += convertHexLengthBytes(data, header_size);
                    }
                }
				for (int j = offset+5; j < header->caplen; j++){
                    if(    (data[j] == 0x16 || data[j] == 0x17 || data[j] == 0x14 || data[j] == 0x15) \
                		&& (data[j+1] == 0x03) \
                		&& (data[j+2] == 0x01 || data[j+2] == 0x02 || data[j+2] == 0x03 || data[j+2] == 0x04)
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
                                offset += 5 + convertHexLengthBytes(data, j);
                                j = offset;
                            }
                        }
					}
                }
            }
            else{
                bool wasAppData = false;
                for (int i = offset; i < header->caplen; i++){
                    bool breakThis = false;
                    if(    (data[i] == 0x16 || data[i] == 0x17 || data[i] == 0x14 || data[i] == 0x15) \
                        && (data[i+1] == 0x03) \
                        && (data[i+2] == 0x01 || data[i+2] == 0x02 || data[i+2] == 0x03 || data[i+2] == 0x04)
                    ){
                        if (data[i] == 0x17){
                            wasAppData = true;
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
                                if (wasAppData && data[i] == 0x14){
                                    break;
                                }
                                if ((header->caplen - i) <= 4){
                                    breakThis = true;
                                    break;
                                }
                                it->bytes += convertHexLengthBytes(data, i);
                                offset += 5 + convertHexLengthBytes(data, i);
                            }
                        }
                    }
                    if (offset > header->caplen || breakThis){
                        break;                
                    } 
                }
            }

            if((data[47] == 0x19 || data[47] == 0x11) || (data[67] == 0x11 && iph->version == 6 && data[20] == 0x06)){
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
                        if (it->wasServerFIN == 1){
                            it->whoFINip = *ipSrc;
                            it->whoFINport = *portSrc;
                        }

                        if (it->wasServerFIN == 2){
                            if ((it->whoFINip != *ipSrc && it->whoFINport != *portSrc) || (it->isSameIP && it->whoFINport != *portSrc)){
                                if (it->isPrintable){
                                    struct timeval endTime;
                                    endTime.tv_sec = header->ts.tv_sec;
                                    endTime.tv_usec = header->ts.tv_usec;
                                    printPacket(&it->bytes, &it->packets, &it->sniRet, &it->ipSrc, &it->ipDest, &it->portSrc, \
                                                it->dateSeconds, it->miliSeconds, it->startTime, endTime);
                                }
                            }
                            else{
                                it->wasServerFIN = 1;
                            }
                        }
                    }
                }
            }
        }
    }
}

list<Packet> Packets;

void gotPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *data)
{
    struct iphdr *iph = (struct iphdr *)(data  + sizeof(struct ethhdr));
    int header_size = calculateHeaderSize(data, iph);

    bool packetAdd = true;
    int offset = header_size;

    string ipSrc;
	string ipDest;
	string portSrc;
    string portDst;
    if (iph->version == 6){
        fillIpsAndPorts6(data, &ipSrc, &ipDest, &portSrc, &portDst);
    }
    else{
        fillIpsAndPorts(data, &ipSrc, &ipDest, &portSrc, &portDst);
    }

    int controlTCP = iph->protocol;

    if (iph->version == 6 && data[20] == 0x06){
        controlTCP = 6;
    }

    if (controlTCP){
        for (auto it = Packets.begin(); it != Packets.end(); it++){
                if (((strcmp(ipSrc.c_str(), it->ipSrc.c_str()) == 0 || \
                    strcmp(ipSrc.c_str(), it->ipDest.c_str()) == 0) && \
                    (strcmp(ipDest.c_str(), it->ipDest.c_str()) == 0 || \
                    strcmp(ipDest.c_str(), it->ipSrc.c_str()) == 0)) && \
                    \
                    ((strcmp(portSrc.c_str(), it->portSrc.c_str()) == 0 || \
                    strcmp(portSrc.c_str(), it->portDst.c_str()) == 0) && \
                    (strcmp(portDst.c_str(), it->portDst.c_str()) == 0 || \
                    strcmp(portDst.c_str(), it->portSrc.c_str()) == 0)))
                {
                    it->packets++;
                    packetAdd = false;
                }
            }

            if (packetAdd || Packets.empty()){
                Packet packet;
                packet.ipSrc = ipSrc;
                packet.ipDest = ipDest;
                packet.portSrc = portSrc;
                packet.portDst = portDst;  

                if (strcmp(ipSrc.c_str(), ipDest.c_str()) == 0){
                    packet.isSameIP = true;
                }
                packet.packets = 1;                  
                packet.dateSeconds = header->ts.tv_sec;
                packet.miliSeconds = header->ts.tv_usec;
                packet.startTime.tv_sec = header->ts.tv_sec;
                packet.startTime.tv_usec = header->ts.tv_usec;
                Packets.push_back(packet);
            }

        if(    (data[header_size] == 0x16 || data[header_size] == 0x17 || data[header_size] == 0x14 || data[header_size] == 0x15) \
            && (data[header_size+1] == 0x03) \
            && (data[header_size+2] == 0x00 || data[header_size+2] == 0x01 || data[header_size+2] == 0x02 || data[header_size+2] == 0x03 || data[header_size+2] == 0x04)
        ){ 
			if(data[header_size] == 0x16 && data[header_size+5] == 0x01){
                    for (auto it = Packets.begin(); it != Packets.end(); it++){
                        if (((strcmp(ipSrc.c_str(), it->ipSrc.c_str()) == 0 || \
                            strcmp(ipSrc.c_str(), it->ipDest.c_str()) == 0) && \
                            (strcmp(ipDest.c_str(), it->ipDest.c_str()) == 0 || \
                            strcmp(ipDest.c_str(), it->ipSrc.c_str()) == 0)) && \
                            \
                            ((strcmp(portSrc.c_str(), it->portSrc.c_str()) == 0 || \
                            strcmp(portSrc.c_str(), it->portDst.c_str()) == 0) && \
                            (strcmp(portDst.c_str(), it->portDst.c_str()) == 0 || \
                            strcmp(portDst.c_str(), it->portSrc.c_str()) == 0)))
                        {
                            it->wasHello = true;
                            it->sniRet = calculateSNI(data, header_size+43).c_str(); //skip to session ID Length
                        }
                    }
			}

            if(data[header_size] == 0x16 && data[header_size+5] == 0x02){
                    for (auto it = Packets.begin(); it != Packets.end(); it++){
                        if (((strcmp(ipSrc.c_str(), it->ipSrc.c_str()) == 0 || \
                            strcmp(ipSrc.c_str(), it->ipDest.c_str()) == 0) && \
                            (strcmp(ipDest.c_str(), it->ipDest.c_str()) == 0 || \
                            strcmp(ipDest.c_str(), it->ipSrc.c_str()) == 0)) && \
                            \
                            ((strcmp(portSrc.c_str(), it->portSrc.c_str()) == 0 || \
                            strcmp(portSrc.c_str(), it->portDst.c_str()) == 0) && \
                            (strcmp(portDst.c_str(), it->portDst.c_str()) == 0 || \
                            strcmp(portDst.c_str(), it->portSrc.c_str()) == 0)))
                        {
                            if (it->wasHello){
                                it->isPrintable = true;
                            }
                        }
                    }
				}

            for (auto it = Packets.begin(); it != Packets.end(); it++){
                if (((strcmp(ipSrc.c_str(), it->ipSrc.c_str()) == 0 || \
                    strcmp(ipSrc.c_str(), it->ipDest.c_str()) == 0) && \
                    (strcmp(ipDest.c_str(), it->ipDest.c_str()) == 0 || \
                    strcmp(ipDest.c_str(), it->ipSrc.c_str()) == 0)) && \
                    \
                    ((strcmp(portSrc.c_str(), it->portSrc.c_str()) == 0 || \
                    strcmp(portSrc.c_str(), it->portDst.c_str()) == 0) && \
                    (strcmp(portDst.c_str(), it->portDst.c_str()) == 0 || \
                    strcmp(portDst.c_str(), it->portSrc.c_str()) == 0)))
                {
                    it->bytes += convertHexLengthBytes(data, header_size);
                    offset += convertHexLengthBytes(data, header_size);
                }
            }

			for (int j = offset+5; j < header->caplen; j++){
                if(    (data[j] == 0x16 || data[j] == 0x17 || data[j] == 0x14 || data[j] == 0x15) \
            		&& (data[j+1] == 0x03) \
            		&& (data[j+2] == 0x00 || data[j+2] == 0x01 || data[j+2] == 0x02 || data[j+2] == 0x03 || data[j+2] == 0x04)
            	){
                    for (auto it = Packets.begin(); it != Packets.end(); it++){
                        if (((strcmp(ipSrc.c_str(), it->ipSrc.c_str()) == 0 || \
                            strcmp(ipSrc.c_str(), it->ipDest.c_str()) == 0) && \
                            (strcmp(ipDest.c_str(), it->ipDest.c_str()) == 0 || \
                            strcmp(ipDest.c_str(), it->ipSrc.c_str()) == 0)) && \
                            \
                            ((strcmp(portSrc.c_str(), it->portSrc.c_str()) == 0 || \
                            strcmp(portSrc.c_str(), it->portDst.c_str()) == 0) && \
                            (strcmp(portDst.c_str(), it->portDst.c_str()) == 0 || \
                            strcmp(portDst.c_str(), it->portSrc.c_str()) == 0)))
                        {
                            it->bytes += convertHexLengthBytes(data, j);
                            offset += 5 + convertHexLengthBytes(data, j);
                            j = offset;
                        }
                    }
				}
            }
        }
        else{
            bool wasAppData = false;
            for (int i = offset; i < header->caplen; i++){
                bool breakThis = false;
                if(    (data[i] == 0x16 || data[i] == 0x17 || data[i] == 0x14 || data[i] == 0x15) \
                    && (data[i+1] == 0x03) \
                    && (data[i+2] == 0x00 || data[i+2] == 0x01 || data[i+2] == 0x02 || data[i+2] == 0x03 || data[i+2] == 0x04)
                ){
                    if (data[i] == 0x17){
                            wasAppData = true;
                    }
                    for (auto it = Packets.begin(); it != Packets.end(); it++){
                        if (((strcmp(ipSrc.c_str(), it->ipSrc.c_str()) == 0 || \
                            strcmp(ipSrc.c_str(), it->ipDest.c_str()) == 0) && \
                            (strcmp(ipDest.c_str(), it->ipDest.c_str()) == 0 || \
                            strcmp(ipDest.c_str(), it->ipSrc.c_str()) == 0)) && \
                            \
                            ((strcmp(portSrc.c_str(), it->portSrc.c_str()) == 0 || \
                            strcmp(portSrc.c_str(), it->portDst.c_str()) == 0) && \
                            (strcmp(portDst.c_str(), it->portDst.c_str()) == 0 || \
                            strcmp(portDst.c_str(), it->portSrc.c_str()) == 0)))
                        {
                            if (wasAppData && data[i] == 0x14){
                                    break;
                                }
                            if ((header->caplen - i) <= 4){
                                breakThis = true;
                                break;
                            }
                            it->bytes += convertHexLengthBytes(data, i);
                            offset += 5 + convertHexLengthBytes(data, i);
                        }
                    }
                }
                if (offset > header->caplen || breakThis){
                    break;                
                } 
            }
        }

        if((data[47] == 0x19 || data[47] == 0x11) || (data[67] == 0x11 && iph->version == 6 && data[20] == 0x06)){
            for (auto it = Packets.begin(); it != Packets.end(); it++){
                if (((strcmp(ipSrc.c_str(), it->ipSrc.c_str()) == 0 || \
                    strcmp(ipSrc.c_str(), it->ipDest.c_str()) == 0) && \
                    (strcmp(ipDest.c_str(), it->ipDest.c_str()) == 0 || \
                    strcmp(ipDest.c_str(), it->ipSrc.c_str()) == 0)) && \
                    \
                    ((strcmp(portSrc.c_str(), it->portSrc.c_str()) == 0 || \
                    strcmp(portSrc.c_str(), it->portDst.c_str()) == 0) && \
                    (strcmp(portDst.c_str(), it->portDst.c_str()) == 0 || \
                    strcmp(portDst.c_str(), it->portSrc.c_str()) == 0)))
                {
                    it->wasServerFIN++;
                    if (it->wasServerFIN == 1){
                        it->whoFINip = ipSrc;
                        it->whoFINport = portSrc;
                    }

                    if (it->wasServerFIN == 2){
                        if ((it->whoFINip != ipSrc && it->whoFINport != portSrc) || (it->isSameIP && it->whoFINport != portSrc)){
                                if (it->isPrintable){
                                struct timeval endTime;
                                endTime.tv_sec = header->ts.tv_sec;
                                endTime.tv_usec = header->ts.tv_usec;
                                printPacket(&it->bytes, &it->packets, &it->sniRet, &it->ipSrc, &it->ipDest, &it->portSrc, \
                                            it->dateSeconds, it->miliSeconds, it->startTime, endTime);
                            }
                        }
                        else{
                            it->wasServerFIN = 1;
                        }
                    }
                }
            }
        }
    }
}

void liveSniffer(string interface)
{
	pcap_t *handle; 
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(interface.c_str(), 65536, 1, 0, errbuf);
	pcap_loop(handle, -1, gotPacket, NULL);
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
            liveSniffer(argv[2]);
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

