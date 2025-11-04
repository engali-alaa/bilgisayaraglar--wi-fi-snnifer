
#!/usr/bin/env python3
"""
wifi_sniffer_simulator.py

Simple Wi-Fi Packet Sniffer Simulator (single-file)
- Simulates packet generation in a background thread
- Displays packets in a Treeview (like Wireshark)
- Filter by protocol / search text
- Shows basic stats and a protocol-distribution pie chart
- Save captured packets to CSV

Requirements:
    python >= 3.8
    pip install matplotlib pandas

Run:
    python wifi_sniffer_simulator.py
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import queue
import time
import random
import datetime
import csv
import sys

# Use TkAgg backend for embedding in Tkinter
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# -------------------- Simulation helpers --------------------
PROTOCOLS = ["TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP"]

def rand_mac():
    return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))

def rand_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def generate_packet(idx):
    """
    Create a simulated packet dictionary.
    """
    proto = random.choices(PROTOCOLS, weights=[40, 20, 10, 10, 10, 10])[0]
    size = random.randint(60, 1500) if proto in ("TCP", "UDP", "HTTP") else random.randint(28, 256)
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

# -------------------- Packet generator thread --------------------
class PacketGenerator(threading.Thread):
    """
    Background thread that generates simulated packets and pushes them to a queue.
    The 'rate' parameter is packets per second (approx).
    """
    def __init__(self, out_q: queue.Queue, rate: float = 5.0):
        super().__init__(daemon=True)
        self.out_q = out_q
        self.rate = max(0.1, float(rate))
        self.running = threading.Event()
        self._counter = 0
        self._stop_event = threading.Event()

    def start_gen(self):
        self.running.set()
        if not self.is_alive():
            self.start()

    def stop_gen(self):
        self.running.clear()

    def stop_thread(self):
        self.running.clear()
        self._stop_event.set()

    def run(self):
        # We keep running to allow restart; thread is daemon for safe exit
        while not self._stop_event.is_set():
            if self.running.is_set():
                self._counter += 1
                pkt = generate_packet(self._counter)
                try:
                    self.out_q.put_nowait(pkt)
                except queue.Full:
                    pass
                # Sleep with jitter (exponential) to simulate bursty traffic
                # mean interval = 1 / rate
                interval = random.expovariate(self.rate)
                # Prevent super tiny sleeps
                time.sleep(max(0.01, interval))
            else:
                time.sleep(0.1)

# -------------------- GUI Application --------------------
class SnifferApp:
    def __init__(self, master):
        self.master = master
        master.title("Wi-Fi Sniffer Simulator")
        master.geometry("1000x660")

        # Main data
        self.packet_q = queue.Queue(maxsize=10000)
        self.packets = []             # all captured packets (list of dicts)
        self.filtered_packets = None  # None means no filter, otherwise list
        self.protocol_counts = {p: 0 for p in PROTOCOLS}

        # Packet generator
        self.generator = PacketGenerator(self.packet_q, rate=6.0)

        # Build UI
        self._build_controls()
        self._build_packet_list()
        self._build_stats_and_plot()

        # Periodic polling
        self.master.after(150, self._poll_queue)

        # Clean up on close
        self.master.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------------- UI building ----------------
    def _build_controls(self):
        ctrl = ttk.Frame(self.master, padding=6)
        ctrl.pack(side="top", fill="x")

        self.start_btn = ttk.Button(ctrl, text="Start", command=self.start)
        self.start_btn.pack(side="left", padx=4)
        self.stop_btn = ttk.Button(ctrl, text="Stop", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=4)

        ttk.Button(ctrl, text="Save CSV", command=self.save_csv).pack(side="left", padx=4)

        ttk.Label(ctrl, text="Protocol:").pack(side="left", padx=(20, 4))
        self.protocol_var = tk.StringVar(value="All")
        self.protocol_cb = ttk.Combobox(ctrl, textvariable=self.protocol_var, values=["All"] + PROTOCOLS, state="readonly", width=10)
        self.protocol_cb.pack(side="left")

        ttk.Label(ctrl, text="Search:").pack(side="left", padx=(10, 4))
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(ctrl, textvariable=self.search_var, width=28)
        self.search_entry.pack(side="left")
        ttk.Button(ctrl, text="Apply", command=self.apply_filter).pack(side="left", padx=4)
        ttk.Button(ctrl, text="Clear", command=self.clear_filter).pack(side="left", padx=4)

    def _build_packet_list(self):
        paned = ttk.Panedwindow(self.master, orient="vertical")
        paned.pack(fill="both", expand=True, padx=6, pady=6)

        frame_list = ttk.Frame(paned)
        paned.add(frame_list, weight=3)

        columns = ("No", "Timestamp", "Src MAC", "Dst MAC", "Src IP", "Dst IP", "Protocol", "Length", "Info")
        self.tree = ttk.Treeview(frame_list, columns=columns, show="headings", height=18)
        for col in columns:
            self.tree.heading(col, text=col)
            if col == "Info":
                self.tree.column(col, width=260, anchor="w")
            elif col in ("Src MAC", "Dst MAC"):
                self.tree.column(col, width=130, anchor="center")
            elif col in ("Src IP", "Dst IP"):
                self.tree.column(col, width=100, anchor="center")
            elif col == "Timestamp":
                self.tree.column(col, width=160)
            else:
                self.tree.column(col, width=80, anchor="center")

        self.tree.pack(side="left", fill="both", expand=True)
        vsb = ttk.Scrollbar(frame_list, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=vsb.set)
        vsb.pack(side="right", fill="y")

    def _build_stats_and_plot(self):
        # bottom frame for stats + plot
        stats_frame = ttk.Frame(self.master)
        stats_frame.pack(fill="x", padx=6, pady=(0,6))

        left = ttk.Frame(stats_frame)
        left.pack(side="left", fill="both", expand=True, padx=(0,6))
        right = ttk.Frame(stats_frame)
        right.pack(side="left", fill="both", expand=True)

        self.total_label = ttk.Label(left, text="Total packets: 0", font=("TkDefaultFont", 11, "bold"))
        self.total_label.pack(anchor="nw", pady=(4,2))
        self.bytes_label = ttk.Label(left, text="Total bytes: 0", font=("TkDefaultFont", 11))
        self.bytes_label.pack(anchor="nw", pady=(0,8))

        self.proto_tree = ttk.Treeview(left, columns=("Protocol", "Count"), show="headings", height=6)
        self.proto_tree.heading("Protocol", text="Protocol")
        self.proto_tree.heading("Count", text="Count")
        self.proto_tree.column("Protocol", width=120, anchor="center")
        self.proto_tree.column("Count", width=80, anchor="center")
        self.proto_tree.pack(anchor="nw")
        for p in PROTOCOLS:
            self.proto_tree.insert("", "end", iid=p, values=(p, 0))

        # Matplotlib figure (pie chart)
        self.fig, self.ax = plt.subplots(figsize=(4, 2.4))
        self.canvas = FigureCanvasTkAgg(self.fig, master=right)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        self.fig.tight_layout()

    # ---------------- Controls actions ----------------
    def start(self):
        self.generator.start_gen()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")

    def stop(self):
        self.generator.stop_gen()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    def save_csv(self):
        if not self.packets:
            messagebox.showinfo("Info", "No packets to save.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files","*.csv")])
        if not path:
            return
        keys = ["No", "Timestamp", "Src MAC", "Dst MAC", "Src IP", "Dst IP", "Protocol", "Length", "Info"]
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                writer.writerows(self.packets)
            messagebox.showinfo("Saved", f"Saved {len(self.packets)} packets to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save CSV:\n{e}")

    def apply_filter(self):
        proto = self.protocol_var.get()
        text = self.search_var.get().strip().lower()
        if proto == "All":
            filtered = self.packets
        else:
            filtered = [p for p in self.packets if p["Protocol"] == proto]
        if text:
            def matches(p):
                hay = " ".join([p["Src IP"], p["Dst IP"], p["Src MAC"], p["Dst MAC"], p["Info"]]).lower()
                return text in hay
            filtered = [p for p in filtered if matches(p)]
        self.filtered_packets = filtered
        self._refresh_tree_from_list(filtered)

    def clear_filter(self):
        self.protocol_var.set("All")
        self.search_var.set("")
        self.filtered_packets = None
        self._refresh_tree_from_list(self.packets[-2000:])  # show last portion

    # ---------------- Queue polling & UI updates ----------------
    def _poll_queue(self):
        updated = False
        while not self.packet_q.empty():
            pkt = self.packet_q.get()
            self.packets.append(pkt)
            updated = True
            # update counts
            self.protocol_counts[pkt["Protocol"]] = self.protocol_counts.get(pkt["Protocol"], 0) + 1
        if updated:
            # if no filter active, append latest row to the tree view
            if self.filtered_packets is None:
                p = self.packets[-1]
                self._insert_tree_row(p)
                # keep tree length bounded to avoid slowdown
                children = self.tree.get_children()
                if len(children) > 2000:
                    for cid in children[:len(children) - 2000]:
                        self.tree.delete(cid)
            self._update_stats_and_plot()
        # schedule next poll
        self.master.after(150, self._poll_queue)

    def _insert_tree_row(self, p):
        vals = (p["No"], p["Timestamp"], p["Src MAC"], p["Dst MAC"], p["Src IP"], p["Dst IP"], p["Protocol"], p["Length"], p["Info"])
        self.tree.insert("", "end", values=vals)

    def _refresh_tree_from_list(self, lst):
        # clear
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        # insert last up to 2000 rows for performance
        source = lst[-2000:]
        for p in source:
            vals = (p["No"], p["Timestamp"], p["Src MAC"], p["Dst MAC"], p["Src IP"], p["Dst IP"], p["Protocol"], p["Length"], p["Info"])
            self.tree.insert("", "end", values=vals)
        self._update_stats_and_plot()

    def _update_stats_and_plot(self):
        total = len(self.packets)
        total_bytes = sum(p["Length"] for p in self.packets)
        self.total_label.config(text=f"Total packets: {total}")
        self.bytes_label.config(text=f"Total bytes: {total_bytes} bytes")
        # update protocol table
        for p in PROTOCOLS:
            cnt = self.protocol_counts.get(p, 0)
            try:
                self.proto_tree.item(p, values=(p, cnt))
            except Exception:
                pass
        # update pie chart
        self.ax.clear()
        counts = [self.protocol_counts.get(p, 0) for p in PROTOCOLS]
        labels = [p for p, c in zip(PROTOCOLS, counts) if c > 0]
        sizes = [c for c in counts if c > 0]
        if sizes:
            self.ax.pie(sizes, labels=labels, autopct='%1.0f%%', startangle=90)
            self.ax.axis('equal')
            self.ax.set_title("Protocol distribution")
        else:
            self.ax.text(0.5, 0.5, "No data", ha="center", va="center")
        self.canvas.draw_idle()

    # ---------------- Shutdown ----------------
    def _on_close(self):
        # Ask user to confirm exit if generator is running
        if self.generator.running.is_set():
            if not messagebox.askokcancel("Exit", "Packet generator is running. Exit anyway?"):
                return
        # Stop and cleanup
        try:
            self.generator.stop_thread()
        except Exception:
            pass
        # allow a short time for thread to stop
        self.master.after(200, self.master.destroy)

# -------------------- Main --------------------
def main():
    root = tk.Tk()
    app = SnifferApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()

