#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int main()
{

    char *device_name, *net_addr, *net_mask;
    int return_code;
    char error[PCAP_ERRBUF_SIZE];

    bpf_u_int32 net_addr_int, net_mask_int; // Ip address as unsigned 32bit integer
    struct in_addr addr;

    device_name = pcap_lookupdev(error);
    printf("%s\n", device_name);
    // device_name = pcap_findalldevs(device_name, error);

    if (device_name == NULL)
    {
        printf("[X] %s\n", error);
        return -1;
    }

    // With a device  in place, acquire the IP address and the Subnet Mask
    return_code = pcap_lookupnet(device_name, &net_addr_int, &net_mask_int, error);
    if (return_code == -1)
    {
        printf("[X] %s\n", error);
        return -1;
    }

    // Convert the 32 bit of IP and Mask into human readable
    addr.s_addr = net_addr_int;
    net_addr = inet_ntoa(addr);

    if (net_addr == NULL)
    {
        printf("inet_ntoa: Error converting IP\n");
        return -1;
    }
    else
    {
        printf("Ip: %s\n", net_addr);
    }

    addr.s_addr = net_mask_int;
    net_mask = inet_ntoa(addr);

    if (net_mask == NULL)
    {
        printf("inet_ntoa: Error converting Mask\n");
        return -1;
    }
    else
    {
        printf("Mask: %s\n", net_mask);
    }
}