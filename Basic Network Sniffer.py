import tkinter as tk
from tkinter import scrolledtext, ttk
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import Counter
packet_counts = Counter({"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0})
capturing = False  # Flag to start/stop sniffing

def process_packet(packet):
    if not capturing:
        return
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        else:
            protocol = "Other"
        packet_counts[protocol] += 1 
        message = f"{protocol} Packet: {src_ip} -> {dst_ip}"

        log_text.insert(tk.END, message + "\n")
        log_text.see(tk.END)

def start_sniffing():
    global capturing
    if capturing:
        return  
    capturing = True
    log_text.insert(tk.END, "[*] Sniffing started...\n")
    sniff_thread = threading.Thread(target=lambda: sniff(prn=process_packet, store=False, filter="tcp or udp or icmp"))
    sniff_thread.daemon = True
    sniff_thread.start()
    ani.event_source.start()
    start_button.config(state=tk.DISABLED) 
    stop_button.config(state=tk.NORMAL)  

def stop_sniffing():
    global capturing
    capturing = False
    log_text.insert(tk.END, "[*] Sniffing stopped.\n")
    ani.event_source.stop()  
    start_button.config(state=tk.NORMAL)  
    stop_button.config(state=tk.DISABLED)  

def update_graph(frame):
    ax1.clear()
    ax2.clear()
    labels = list(packet_counts.keys())
    sizes = list(packet_counts.values())
    if sum(sizes) == 0:
        return  
    ax1.pie(sizes, labels=labels, autopct='%1.1f%%', colors=['blue', 'green', 'red', 'gray'])
    ax1.set_title("Traffic Distribution (Live)")
    ax2.bar(labels, sizes, color=['blue', 'green', 'red', 'gray'])
    ax2.set_xlabel("Protocol Type")
    ax2.set_ylabel("Number of Packets")
    ax2.set_title("Traffic Analysis (Live)")
root = tk.Tk()
root.title("Live Network Sniffer")
root.geometry("800x600") 
frame_top = tk.Frame(root)
frame_top.pack(side=tk.TOP, pady=10)
start_button = ttk.Button(frame_top, text="Start Sniffing", command=start_sniffing)
stop_button = ttk.Button(frame_top, text="Stop Sniffing", command=stop_sniffing, state=tk.DISABLED)
start_button.pack(side=tk.LEFT, padx=10)
stop_button.pack(side=tk.LEFT, padx=10)
log_text = scrolledtext.ScrolledText(root, width=80, height=15)
log_text.pack(pady=10)
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
canvas = FigureCanvasTkAgg(fig, master=root)
canvas.get_tk_widget().pack()
ani = FuncAnimation(fig, update_graph, interval=1000, cache_frame_data=False)
root.mainloop()

