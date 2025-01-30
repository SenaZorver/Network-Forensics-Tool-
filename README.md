# Network-Forensics-Tool-
Network Forensics Tool

📌 Projenin Amacı ve Genel İşleyişi

Bu proje, ağ trafiği analizini gerçekleştiren ve adli bilişim için kullanılabilen bir ağ adli analiz aracıdır.
Temel işlevleri:

✔ Paket Yakalama: Ağ trafiğindeki bireysel paketleri yakalar ve analiz eder.
✔ Akış Yeniden Yapılandırma: Veri akışlarını bütünsel olarak incelemek için ağ akışlarını yeniden oluşturur.
✔ Protokol Analizi: Farklı ağ protokollerini analiz eder ve anormallikleri tespit eder.


---

👤 Proje Sahibi

Ad Soyad: Sena Zorver
Öğrenci Numarası: 2320191012


---

📦 Kullanılan Kütüphaneler ve Versiyonları

Aşağıdaki Python kütüphaneleri projede kullanılmıştır:

scapy (2.5.0) → Paket analizi ve manipülasyonu için.

pyshark (0.6) → PCAP dosyalarını analiz etme ve canlı trafik yakalama için.

dpkt (1.9.8) → Düşük seviyeli PCAP analizi ve protokol ayrıştırma için.

tshark (Wireshark 4.0.0) → Komut satırından paket analizi için.

json (Yerleşik) → Verileri JSON formatında işlemek için.



---

🛠 Gerekli Araçlar ve Kurulum Gereksinimleri

Projenin çalıştırılabilmesi için aşağıdaki bileşenler gereklidir:

Python 3.10 → Programın çalıştırılması için.

Wireshark → Ağ trafiğini yakalamak ve analiz etmek için.

Tshark → Komut satırından paket analizi yapmak için.

Libpcap → Linux sistemlerde paket yakalama için.

Pip → Python kütüphanelerini yüklemek için.



---

⚙️ Kurulum ve Çalıştırma

1️⃣ Python ve Gerekli Araçları Yükleyin

Öncelikle, Python 3.10'u kurun.

Aşağıdaki komutlarla Wireshark ve Tshark'ı yükleyin:

sudo apt install wireshark tshark  # Linux için
brew install wireshark tshark      # macOS için

Windows kullanıyorsan Wireshark'ın resmi sitesinden indirebilirsin: Wireshark Download


---

2️⃣ Projeyi İndirin ve Gerekli Bağımlılıkları Kurun

Proje deposunu GitHub üzerinden klonlayın:

git clone <repository_url>
cd <repository_folder>

Gerekli Python kütüphanelerini yüklemek için:

pip install -r requirements.txt


---

🚀 Çalıştırma

PCAP dosyası analizi için:

python network_forensics.py --pcap trafik.pcap --mode packet --output result.json

Gerçek zamanlı analiz için:

python network_forensics.py --live_capture --output realtime.json

Belirli bir IP için analiz:

python network_forensics.py --pcap trafik.pcap --filter "ip 192.168.1.1" --output filtered.json


---

⚙️ Zorunlu Çalışma Parametreleri


---

🔧 Opsiyonel Parametreler


---

📌 "Network Forensics Tool" Temel Python Kodu

✔ Packet Capture Analysis: .pcap dosyasını okuyarak paketleri analiz eder.
✔ Flow Reconstruction: IP adreslerine göre trafik akışını yeniden yapılandırır.
✔ Protocol Analysis: Protokol bazlı istatistikler oluşturur.
✔ JSON Formatında Çıktı Üretir.


---

📌 Kod Açıklaması

Paket Analizi (packet mode) → PCAP dosyasındaki tüm paketleri analiz eder, kaynak/destinasyon IP ve protokol bilgilerini çıkarır.

Akış Yeniden Yapılandırma (flow mode) → IP çiftlerine göre trafiği gruplar.

Protokol Analizi (protocol mode) → Kullanılan protokollerin istatistiklerini çıkarır.

JSON Çıktı Üretir ve Dosyaya Kaydeder.



---

📜 Lisans

Bu proje MIT Lisansı ile lisanslanmıştır. Daha fazla bilgi için LICENSE dosyasını inceleyebilirsiniz.
