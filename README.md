# Network-Forensics-Tool-
Network Forensics Tool 
Projenin Amacı ve Genel İşleyişi
Bu proje, ağ trafiği analizini gerçekleştiren ve adli bilişim için kullanılabilen bir ağ adli analiz aracıdır. Paket yakalama, akış yeniden yapılandırma ve protokol analizi işlemlerini yapar.

•	Ağ trafiğindeki bireysel paketleri yakalar ve analiz eder.
•	Ağ akışlarını yeniden yapılandırarak veri akışlarını bütünsel olarak inceler.
•	Farklı ağ protokollerini analiz ederek anormallikleri tespit eder.
________________________________________
Proje Sahibi Bilgileri
Proje Sahibi	Öğrenci Numarası
Sena Zorver	2320191012
Kullanılan Kütüphaneler ve Versiyonları
Proje, aşağıdaki Python kütüphanelerini kullanmaktadır:
•	“scapy": "2.5.0", // Paket analizi ve manipülasyonu için.
•	"pyshark": "0.6", // PCAP dosyalarını analiz etme ve canlı trafik yakalamak için.
•	"dpkt": "1.9.8", // Düşük seviyeli PCAP analizi ve protokol ayrıştırma için.
•	"tshark": "Wireshark 4.0.0", // Canlı trafik yakalama ve paket ayrıştırma için.
•	"json": "Yerleşik Python kütüphanesi" // Verileri JSON formatında işleme için
________________________________________
Gerekli Araçlar ve Kurulum Gereksinimleri
Projenin çalıştırılması için aşağıdaki araç ve gereksinimlere ihtiyacınız vardır:
•	Python 3.10 "Programın çalıştırılması için gereklidir."
•	Wireshark  "Ağ trafiğini yakalamak ve analiz etmek için gereklidir."
•	Tshark "Komut satırından paket analiz etmek için kullanılır."
•	Libpcap "Linux sistemlerde paket yakalama için gereklidir."
•	Pip  "Python kütüphanelerini yüklemek için gereklidir."


Gerekli kütüphaneleri yüklemek için aşağıdaki komut çalıştırılabilir:
pip install -r requirements.txt
________________________________________
Zorunlu Çalışma Parametreleri
•	"--pcap": "Analiz edilecek pcap dosyasının yolu."
•	"--mode": "Çalışma modu: packet, flow, protocol."
•	"--output": "JSON formatında çıktının kaydedileceği dosya."

________________________________________
Opsiyonel Parametreler ve Kullanımları
•	"--filter": "Belirli bir IP, port veya protokol için filtreleme yapar."
•	"--live_capture": "Gerçek zamanlı paket yakalama modu."
•	"--verbose": "Detaylı log çıktısı sağlar."
________________________________________
Kurulum ve Çalıştırma Talimatları
1.	Python 3.10'u yükleyin.
2.	Proje deposunu klonlayın veya dosyaları indirin:
3.	git clone <repository_url>
cd <repository_folder>
4.	Gerekli Python kütüphanelerini yükleyin:
                     pip install scapy pyshark dpkt
5.	Wireshark ve Tshark’ı sisteminize kurun
Çalıştırmak için;
“Pcap dosyası analizi: `python network_forensics.py --pcap trafik.pcap --mode packet --output result.json`", 
"Gerçek zamanlı analiz: `python network_forensics.py --live_capture --output realtime.json`", 
"Belirli bir IP için analiz: `python network_forensics.py --pcap trafik.pcap --filter 'ip 192.168.1.1' --output filtered.json`"

________________________________________
"Network Forensics Tool" İçin Temel Bir Python Kodu
✅ Packet Capture Analysis: .pcap dosyasını okuyarak paketleri analiz eder.
✅ Flow Reconstruction: IP adreslerine göre trafik akışını yeniden yapılandırır.
✅ Protocol Analysis: Protokol bazlı istatistikler oluşturur.
✅ JSON Formatında Çıktı Üretir
📌 Kod Açıklaması
•	Paket Analizi (packet mode): PCAP dosyasındaki tüm paketleri analiz eder, kaynak/destinasyon IP ve protokol bilgilerini çıkarır.
•	Akış Yeniden Yapılandırma (flow mode): IP çiftlerine göre trafiği gruplar.
•	Protokol Analizi (protocol mode): Kullanılan protokollerin istatistiklerini çıkarır.
•	JSON Çıktı Üretir ve dosyaya kaydeder.
