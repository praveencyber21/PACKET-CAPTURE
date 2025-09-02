#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <sys/types.h>
#include <time.h>

int main()
{

    const char *device_name;
    char error[PCAP_ERRBUF_SIZE];
    pcap_t *packet_desc;
    const u_char *packet, *destination_addr, *source_addr;
    struct pcap_pkthdr header;
    struct ether_header *eptr;

    /**
     * pcap_lookupdev() finds the default network device which to capture,
     * returns a pointer to a string(device name).
     */
    device_name = pcap_lookupdev(error);

    if (device_name == NULL)
    {
        printf("%s\n", error);
        return -1;
    }
    else
    {
        printf("Device name: %s\n", device_name);
    }

    /**
     * pcap_open_live() open device for capturing.
     *
     * args:
     *      device_name -   (const char *) a string that specifies the network device.
     *                      "any" or NULL can be used to capture packets from all interfaces.
     *      BUFSIZ      -   snapshot length
     *      promisc     -   put into "promiscuous mode"
     *      to_ms       -   packet buffer timeout. If packet available retruns immediately other wise return after specified time.
     *      errbuf      -   holds the error message.
     *
     */
    packet_desc = pcap_open_live(device_name, BUFSIZ, 1, 1000, error);

    if (packet_desc == NULL)
    {
        printf("%s\n", error);
        return -1;
    }
    else
    {
        /**
         * pcap_next() reads the next packet and returns  a u_char pointer,
         * if an error occured it returns NULL.
         */
        packet = pcap_next(packet_desc, &header);

        if (packet == NULL)
        {
            printf("Error: Cannot capture packet\n");
            return -1;
        }
        else
        {
            printf("Received  a packet with length: %d\n", header.len);
            printf("Received at %s\n", ctime((const time_t *)&header.ts.tv_sec));

            // ether_header used to get ethernet destination, source, and type
            eptr = (struct ether_header *)packet;

            // check ethernet type is ip
            if (ntohs(eptr->ether_type) == ETHERTYPE_IP)
            {
                printf("Ethernet type hex: 0x%x; dec: %d is an IP pocket.\n", ETHERTYPE_IP, ETHERTYPE_IP);
            }
            // check ethernet type is arp
            else if (ntohs(eptr->ether_type) == ETHERTYPE_ARP)
            {
                printf("Ethernet type hex: 0x%x; dec: %d is an ARP pocket.\n", ETHERTYPE_ARP, ETHERTYPE_ARP);
            }
            else
            {
                printf("Ethernet type hex: 0x%x; dec: %d is not IP or ARP pocket\n", ntohs(eptr->ether_type), ntohs(eptr->ether_type));
            }

            // Get a destination mac address
            destination_addr = eptr->ether_dhost;
            printf("Destination address: ");

            int i = ETHER_ADDR_LEN;

            for (int i = 0; i < ETHER_ADDR_LEN; i++)
            {
                printf("%s%02x", (i == 0) ? "" : ":", destination_addr[i]);
            }
            printf("\n");

            // Get a source mac address
            source_addr = eptr->ether_shost;
            printf("Source address: ");
            for (int i = 0; i < ETHER_ADDR_LEN; i++)
            {
                printf("%s%02x", (i == 0) ? "" : ":", source_addr[i]);
            }
        }
        printf("\n");
    }
    return 0;
}