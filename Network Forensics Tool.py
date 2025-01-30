import argparse
import json
import pyshark
import scapy.all as scapy
def packet_capture_analysis(pcap_file):
    packets = pyshark.FileCapture(pcap_file)
    packet_list = []
    for packet in packets:
        try:
            packet_info = {
                "timestamp": packet.sniff_time.isoformat(),
                "src_ip": packet.ip.src if hasattr(packet, 'ip') else "N/A",
                "dst_ip": packet.ip.dst if hasattr(packet, 'ip') else "N/A",
                "protocol": packet.highest_layer
            }
            packet_list.append(packet_info)
        except AttributeError:
            continue
    return packet_list

def live_packet_capture(interface, output_file):
    packets = scapy.sniff(iface=interface, count=10)
    packet_list = []
    for packet in packets:
        packet_info = {
            "timestamp": packet.time,
            "src_ip": packet[scapy.IP].src if packet.haslayer(scapy.IP) else "N/A",
            "dst_ip": packet[scapy.IP].dst if packet.haslayer(scapy.IP) else "N/A",
            "protocol": packet.sprintf("%IP.proto%")
        }
        packet_list.append(packet_info)
    with open(output_file, 'w') as f:
        json.dump(packet_list, f, indent=4)
    print(f"Gerçek zamanlı trafik yakalama tamamlandı. Çıktı: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Network Forensics Tool")
    parser.add_argument("--pcap", help="Analiz edilecek pcap dosyasının yolu.")
    parser.add_argument("--live_capture", action="store_true", help="Gerçek zamanlı paket yakalama modu.")
    parser.add_argument("--interface", default="eth0", help="Gerçek zamanlı trafik için ağ arayüzü.")
    parser.add_argument("--output", required=True, help="JSON formatında çıktının kaydedileceği dosya.")
    args = parser.parse_args()

    if args.live_capture:
        live_packet_capture(args.interface, args.output)
    elif args.pcap:
        result = packet_capture_analysis(args.pcap)
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=4)
        print(f"Analiz tamamlandı. Çıktı: {args.output}")
    else:
        print("Lütfen ya --pcap ya da --live_capture parametresini kullanın.")

if __name__ == "__main__":
    main()
