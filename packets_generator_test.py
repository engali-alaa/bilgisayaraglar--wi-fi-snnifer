# packets_generator_test.py
import random, datetime, csv

PROTOCOLS = ["TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP"]

def rand_mac():
    return ":".join(f"{random.randint(0,255):02x}" for _ in range(6))

def rand_ip():
    return ".".join(str(random.randint(1,254)) for _ in range(4))

def generate_packet(idx):
    proto = random.choices(PROTOCOLS, weights=[40,20,10,10,10,10])[0]
    size = random.randint(60,1500) if proto in ("TCP","UDP","HTTP") else random.randint(28,256)
    return {
        "No": idx,
        "Timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "Src MAC": rand_mac(),
        "Dst MAC": rand_mac(),
        "Src IP": rand_ip(),
        "Dst IP": rand_ip(),
        "Protocol": proto,
        "Length": size,
        "Info": f"Simulated {proto} packet"
    }

if __name__ == "__main__":
    packets = [generate_packet(i+1) for i in range(50)]
    # احفظ كـ CSV
    with open("sample_packets.csv", "w", newline="") as f:
        keys = ["No","Timestamp","Src MAC","Dst MAC","Src IP","Dst IP","Protocol","Length","Info"]
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(packets)
    print("Generated 50 packets -> sample_packets.csv")
