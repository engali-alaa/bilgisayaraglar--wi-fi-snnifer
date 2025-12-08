# 📡wi-fi sniffer Bilgisayar ağlar DR.Hasan Serdar 

## 🧠 Overview
**Wi-Fi Sniffer Simulator**, Wireshark benzeri bir arayüzde **ağ paketlerini simüle eden** ve **canlı olarak görüntüleyen** Python tabanlı bir uygulamadır.  
Gerçek ağ trafiği yerine, sistem rastgele üretilen TCP, UDP, ICMP, ARP, DNS ve HTTP paketlerini kullanır.  

Uygulama, **Tkinter GUI** ile görsel arayüz sunar ve aynı zamanda **matplotlib** ile protokol dağılım grafiği oluşturur.  
İstersen yakalanan tüm paketleri **CSV dosyası** olarak dışa da aktarabilirsin.  

🎥 **Tanıtım videosu YouTube’da mevcut:**  
👉 [https://youtu.be/ZXIyFSEdeYI](https://youtu.be/ZXIyFSEdeYI)

---

## ⚙️ Özellikler  

✅ Gerçek zamanlı **paket simülasyonu**  
✅ **Protokol filtreleme** (TCP, UDP, ICMP, ARP, DNS, HTTP)  
✅ **Arama** (IP, MAC veya Info alanına göre)  
✅ **Canlı istatistik ve protokol dağılım pastası**  
✅ **CSV formatında dışa aktarma**  
✅ **Durdur / Başlat kontrolü**  
✅ Python 3.8+ ile uyumlu  

---

## 🧩 Dosya Yapısı  

```
📁 wifi-sniffer-simulator/
├── wifi_sniffer_simulator.py     # Ana uygulama (GUI + Simülasyon)
├── packets_generator_test.py     # Test amaçlı 50 örnek paket üretici
└── README.md                     # Bu dosya
```

---

## 🖥️ Kurulum  

### 1️⃣ Gerekli kütüphaneler  
```bash
pip install matplotlib pandas
```

### 2️⃣ Çalıştır  
```bash
python wifi_sniffer_simulator.py
```

İstersen test verisi üretmek için:  
```bash
python packets_generator_test.py
```
Bu komut, `sample_packets.csv` adlı 50 adet örnek ağ paketi oluşturur.

---

## 📊 Uygulama Arayüzü  

- Üst kısımda **Başlat / Durdur** butonları  
- **Protokol filtresi** ve **arama çubuğu**  
- Orta bölümde **canlı paket listesi (TreeView)**  
- Alt bölümde **istatistikler + protokol dağılımı grafiği (pie chart)**  

---

## 📽️ YouTube Videosu  

🎬 Bu proje YouTube’da tanıtılmıştır:  
👉 [https://youtu.be/ZXIyFSEdeYI](https://youtu.be/ZXIyFSEdeYI)

---

## 👨‍💻 Geliştirici  

**Ali I.** — Bilgisayar Mühendisi  
💡 Yapay zeka, drone sistemleri ve ağ analizine ilgilidir.  
💬 Proje önerileri ve işbirlikleri için katkıya açıktır!  

---

## 🪪 Lisans  
Bu proje **MIT Lisansı** altındadır.  
Dilediğiniz gibi kullanabilir, geliştirebilir ve paylaşabilirsiniz.
