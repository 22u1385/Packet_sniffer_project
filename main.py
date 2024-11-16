from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from scapy.all import sniff, IP
import threading

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Mount the static directory
app.mount("/static", StaticFiles(directory="static"), name="static")

# Global variables
captured_packets = []
capture_thread = None
capture_running = False  # Flag to control packet capture

# Function to capture packets
def packet_capture():
    global capture_running
    def process_packet(packet):
        global captured_packets
        if capture_running and IP in packet:  # Only append packets with IP layer
            packet_info = {
                "summary": packet.summary(),
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "protocol": packet[IP].proto
            }
            captured_packets.append(packet_info)
            
            # Print packet details to the terminal in the specified format
            print(f"Summary: {packet_info['summary']}, Source IP: {packet_info['src_ip']}, "
                  f"Destination IP: {packet_info['dst_ip']}, Protocol: {packet_info['protocol']}")

    sniff(prn=process_packet, store=0)  # Non-blocking packet capture

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "packets": captured_packets})

@app.post("/start_capture")
async def start_capture():
    global capture_thread, capture_running
    if not capture_running:  # Start capture only if not already running
        capture_running = True
        captured_packets.clear()  # Clear packets when starting a new capture
        capture_thread = threading.Thread(target=packet_capture)
        capture_thread.daemon = True
        capture_thread.start()
    return {"message": "Packet capture started."}

@app.post("/stop_capture")
async def stop_capture():
    global capture_running
    capture_running = False
    return {"message": "Packet capture stopped."}

@app.post("/clear_packets")
async def clear_packets():
    global captured_packets
    captured_packets = []
    return {"message": "Captured packets cleared."}

@app.get("/get_packets")
async def get_packets():
    return {"packets": captured_packets}