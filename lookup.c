#include <stdio.h>
#include <pcap.h>

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
        printf("#%d: %s\n", i++, temp->name);
    }

    return 0;
}