#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>   // IP header
#include <netinet/tcp.h>  // TCP header
#include <netinet/udp.h>  // UDP header
#include <netinet/ether.h> // Ethernet header
#include <arpa/inet.h>    // inet_ntoa

using namespace std;

// Callback function for packet processing
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;

    // Check if the packet is IP
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        cout << "Captured Packet:" << endl;
        cout << "Source IP: " << inet_ntoa(ip_header->ip_src) << endl;
        cout << "Destination IP: " << inet_ntoa(ip_header->ip_dst) << endl;

        // Check protocol type
        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            cout << "Protocol: TCP" << endl;
            cout << "Source Port: " << ntohs(tcp_header->source) << endl;
            cout << "Destination Port: " << ntohs(tcp_header->dest) << endl;
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            cout << "Protocol: UDP" << endl;
            cout << "Source Port: " << ntohs(udp_header->source) << endl;
            cout << "Destination Port: " << ntohs(udp_header->dest) << endl;
        } else {
            cout << "Protocol: Other" << endl;
        }

        cout << "---------------------------------------------" << endl;
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE]; // Error buffer
    pcap_if_t *all_devices, *device;
    pcap_t *handle;

    // Get list of available devices
    if (pcap_findalldevs(&all_devices, errbuf) == -1) {
        cerr << "Error finding devices: " << errbuf << endl;
        return 1;
    }

    cout << "Available Devices:" << endl;
    int i = 0;
    for (device = all_devices; device != nullptr; device = device->next) {
        cout << ++i << ". " << device->name;
        if (device->description)
            cout << " (" << device->description << ")";
        cout << endl;
    }

    if (i == 0) {
        cerr << "No devices found! Make sure you run the program with the right permissions." << endl;
        return 1;
    }

    // Select device
    int dev_choice;
    cout << "Enter the number of the device to sniff: ";
    cin >> dev_choice;

    if (dev_choice < 1 || dev_choice > i) {
        cerr << "Invalid device selection." << endl;
        return 1;
    }

    // Get the selected device
    device = all_devices;
    for (int j = 1; j < dev_choice; j++) {
        device = device->next;
    }

    cout << "Sniffing on device: " << device->name << endl;

    // Open the device for capturing
    handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        cerr << "Error opening device: " << errbuf << endl;
        return 1;
    }

    // Start capturing packets
    pcap_loop(handle, 0, packet_handler, nullptr);

    // Close the handle
    pcap_close(handle);
    pcap_freealldevs(all_devices);
    return 0;
}
