#include <stdio.h>
#include <pcap.h>

// Colors
#define RESET "\033[0m"
#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define CYAN "\033[36m"
#define BOLD "\033[1m"

int main(int argc, char *argv[])
{

    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces, *temp;

    int i = 0;

    if (pcap_findalldevs(&interfaces, error) == -1)
    {
        printf("[X] Cannot list the devices.");
        return -1;
    }

    printf("[*] The available network interfaces are: \n");

    for (temp = interfaces; temp; temp = temp->next)
    {
        printf(CYAN "=============================================\n" RESET);
        printf(BOLD " Interface: %s\n" RESET, temp->name);
        printf(CYAN "=============================================\n" RESET);

        if (temp->addresses)
        {
            struct sockaddr_in *addr = (struct sockaddr_in *)temp->addresses->addr;
            struct sockaddr_in *netmask = (struct sockaddr_in *)temp->addresses->netmask;
            struct sockaddr_in *broadaddr = (struct sockaddr_in *)temp->addresses->broadaddr;
            temp->addresses->addr->printf("  " BOLD "Address Information:" RESET "\n");
            printf("    - IP Address   : %s%s%s\n", GREEN, addr ? inet_ntoa(addr->sin_addr) : "N/A", RESET);
            printf("    - Netmask      : %s%s%s\n", YELLOW, netmask ? inet_ntoa(netmask->sin_addr) : "N/A", RESET);
            printf("    - Broadcast    : %s%s%s\n", RED, broadaddr ? inet_ntoa(broadaddr->sin_addr) : "N/A", RESET);
        }
        else
        {
            printf("  " BOLD "Address Information:" RESET " N/A\n");
        }

        printf("  " BOLD "Description:" RESET " %s\n\n",
               temp->description ? temp->description : "N/A");
    }
    return 0;
}