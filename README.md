# network packet sniffer and analyzer

this project is a basic network packet sniffer and analyzer written in python using the `scapy` library. the script captures network packets on a specified interface and prints out detailed information about the packets, including source and destination ip addresses, ports, and protocol types.

## features

- capture and analyze packets for tcp, udp, and arp protocols.
- display source and destination ip addresses and ports.
- handle arp requests and replies.
- real-time packet sniffing on a specified network interface.

## requirements

- python 3.x
- `scapy` library

## installation

1. **clone the repository**:
    ```bash
    git clone https://github.com/yourusername/network-packet-analyzer.git
    cd network-packet-sniffer
    ```

2. **install the required python libraries**:
    ```bash
    pip install scapy
    ```

## usage

1. **run the script**:
    ```bash
    sudo python3 main.py
    ```

    **note**: running a packet sniffer typically requires elevated permissions. use `sudo` on linux or run as administrator on windows.

2. **specify the network interface**:
    modify the `interface` variable in the `packet_sniffer.py` script to the appropriate network interface on your system (e.g., `eth0` for ethernet, `wlan0` for wi-fi on linux, or the interface name on windows).

    ```python
    interface = "eth0"
    ```

3. **start sniffing**:
    the script will start capturing packets on the specified interface and print out details in the console.

## example output

