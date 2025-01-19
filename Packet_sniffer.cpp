#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <cstring>
#include <stdexcept>

using namespace std;

// Function for validating the selected device
pcap_if_t* select_device(pcap_if_t *all_devices, int dev_choice) {
    int count = 0;
    for (pcap_if_t *device = all_devices; device != nullptr; device = device->next, count++) {
        if (count + 1 == dev_choice) return device;
    }
    throw invalid_argument("Invalid device selection.");
}

// Function for adding BPF filter
void apply_filter(pcap_t *handle, const string &filter_expr) {
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_expr.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        throw runtime_error("Error compiling filter: " + string(pcap_geterr(handle)));
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        throw runtime_error("Error setting filter: " + string(pcap_geterr(handle)));
    }
}

// Packet handler
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        cout << "Captured Packet:" << endl;
        cout << "Source IP: " << inet_ntoa(ip_header->ip_src) << endl;
        cout << "Destination IP: " << inet_ntoa(ip_header->ip_dst) << endl;

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
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *all_devices;

    if (pcap_findalldevs(&all_devices, errbuf) == -1) {
        cerr << "Error finding devices: " << errbuf << endl;
        return 1;
    }

    cout << "Available Devices:" << endl;
    int i = 0;
    for (pcap_if_t *device = all_devices; device != nullptr; device = device->next) {
        cout << ++i << ". " << device->name;
        if (device->description)
            cout << " (" << device->description << ")";
        cout << endl;
    }

    if (i == 0) {
        cerr << "No devices found! Check permissions." << endl;
        return 1;
    }

    cout << "Enter the number of the device to sniff: ";
    int dev_choice;
    cin >> dev_choice;

    try {
        pcap_if_t *selected_device = select_device(all_devices, dev_choice);

        pcap_t *handle = pcap_open_live(selected_device->name, BUFSIZ, 1, 1000, errbuf);
        if (!handle) throw runtime_error("Error opening device: " + string(errbuf));

        cout << "Sniffing on device: " << selected_device->name << endl;

        // Apply BPF filter for only TCP and UDP traffic
        apply_filter(handle, "ip and (tcp or udp)");

        pcap_loop(handle, 0, packet_handler, nullptr);

        pcap_close(handle);
    } catch (const exception &e) {
        cerr << "Error: " << e.what() << endl;
    }

    pcap_freealldevs(all_devices);
    return 0;
}
