#canlı trafik yakalama özelliği eklendi
import json
import pyshark
from collections import defaultdict

def analyze_pcap(pcap_file, mode, output_file, filter_expression=None):
    cap = pyshark.FileCapture(pcap_file, display_filter=filter_expression)
    
    result = {
        "file": pcap_file,
        "mode": mode,
        "analysis": {}
    }
    
    if mode == "packet":
        result["analysis"] = packet_analysis(cap)
    elif mode == "flow":
        result["analysis"] = flow_reconstruction(cap)
    elif mode == "protocol":
        result["analysis"] = protocol_analysis(cap)
    else:
        raise ValueError("Geçersiz analiz modu")
    
    with open(output_file, "w") as f:
        json.dump(result, f, indent=4)
    
    print(f"Analiz tamamlandı. Çıktı: {output_file}")

def packet_analysis(cap):
    packets = []
    for pkt in cap:
        packets.append({
            "timestamp": pkt.sniff_time.isoformat(),
            "src_ip": pkt.ip.src if hasattr(pkt, "ip") else "N/A",
            "dst_ip": pkt.ip.dst if hasattr(pkt, "ip") else "N/A",
            "protocol": pkt.highest_layer
        })
    return packets

def flow_reconstruction(cap):
    flows = defaultdict(list)
    for pkt in cap:
        if hasattr(pkt, "ip"):
            flow_key = f"{pkt.ip.src} -> {pkt.ip.dst}"
            flows[flow_key].append(pkt.sniff_time.isoformat())
    return dict(flows)

def protocol_analysis(cap):
    protocol_count = defaultdict(int)
    for pkt in cap:
        protocol_count[pkt.highest_layer] += 1
    return dict(protocol_count)

def live_capture(interface, duration, output_file):
    cap = pyshark.LiveCapture(interface=interface)
    
    packets = []
    for pkt in cap.sniff_continuously(packet_count=duration):
        packets.append({
            "timestamp": pkt.sniff_time.isoformat(),
            "src_ip": pkt.ip.src if hasattr(pkt, "ip") else "N/A",
            "dst_ip": pkt.ip.dst if hasattr(pkt, "ip") else "N/A",
            "protocol": pkt.highest_layer
        })
    
    with open(output_file, "w") as f:
        json.dump(packets, f, indent=4)
    
    print(f"Canlı trafik yakalama tamamlandı. Çıktı: {output_file}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Network Forensics Tool")
    parser.add_argument("--pcap", required=False, help="Analiz edilecek pcap dosyası")
    parser.add_argument("--mode", required=False, choices=["packet", "flow", "protocol"], help="Çalışma modu")
    parser.add_argument("--output", required=True, help="JSON çıktısının kaydedileceği dosya")
    parser.add_argument("--filter", required=False, help="Opsiyonel olarak IP veya protokol filtresi")
    parser.add_argument("--live", required=False, help="Canlı trafik yakalama için ağ arayüzü")
    parser.add_argument("--duration", type=int, required=False, help="Canlı trafik için yakalanacak paket sayısı")
    
    args = parser.parse_args()
    
    if args.live:
        if not args.duration:
            raise ValueError("Canlı trafik yakalamak için --duration parametresi gereklidir.")
        live_capture(args.live, args.duration, args.output)
    else:
        if not args.pcap or not args.mode:
            raise ValueError("PCAP analizi için --pcap ve --mode parametreleri gereklidir.")
        analyze_pcap(args.pcap, args.mode, args.output, args.filter)
