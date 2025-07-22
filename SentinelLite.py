import psutil
import os
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ------------------------------------
# CONFIGURATION
# ------------------------------------
WATCH_PATH = os.path.expanduser("~/Desktop")  # Monitored folder
SUSPICIOUS_EXTENSIONS = ('.enc', '.locked', '.xyz', '.exe', '.dll', '.bat', '.vbs')
SUSPICIOUS_PROCESSES = ['mimikatz.exe', 'powershell.exe', 'cmd.exe', 'pythonw.exe']
SUSPICIOUS_PARENTS = ['winword.exe', 'excel.exe']
COMMON_PORTS = {80, 443, 22, 21, 25, 53}
PROCESS_SURGE_THRESHOLD = 50

# ------------------------------------
# LOGGING SETUP
# ------------------------------------
logging.basicConfig(
    filename="edr_alerts.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ------------------------------------
# FILE EVENT MONITOR
# ------------------------------------
class EDRFileEventHandler(FileSystemEventHandler):
    def __init__(self):
        self.rename_count = 0
        self.delete_count = 0
        self.start_time = time.time()

    def on_moved(self, event):
        self.rename_count += 1
        if time.time() - self.start_time < 10 and self.rename_count > 10:
            logging.warning("🚨 Rapid file renaming — possible ransomware!")
            self.rename_count = 0

    def on_deleted(self, event):
        self.delete_count += 1
        if self.delete_count > 20:
            logging.warning("🔥 Mass file deletion detected!")

    def on_created(self, event):
        if event.src_path.endswith(SUSPICIOUS_EXTENSIONS):
            logging.warning(f"⚠️ Suspicious file created: {event.src_path}")

# ------------------------------------
# CPU/MEMORY & PROCESS MONITOR
# ------------------------------------
def detect_behavior(cpu_thresh=80.0, mem_thresh=50.0):
    flagged_pids = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'ppid']):
        try:
            name = proc.info['name'].lower()
            pid = proc.info['pid']
            cpu = proc.info['cpu_percent']
            mem = proc.info['memory_percent']
            ppid = proc.info['ppid']

            if cpu > cpu_thresh:
                logging.warning(f"High CPU usage: {name} (PID {pid})")
                flagged_pids.append(pid)

            if mem > mem_thresh:
                logging.warning(f"High Memory usage: {name} (PID {pid})")
                flagged_pids.append(pid)

            if name in SUSPICIOUS_PROCESSES:
                logging.warning(f"Suspicious process running: {name} (PID {pid})")
                flagged_pids.append(pid)

            parent = psutil.Process(ppid)
            if parent.name().lower() in SUSPICIOUS_PARENTS and name == 'powershell.exe':
                logging.warning(f"⚠️ Office app spawned PowerShell! {parent.name()} -> {name}")
                flagged_pids.append(pid)

        except Exception:
            continue
    return flagged_pids

# ------------------------------------
# NETWORK MONITOR
# ------------------------------------
def monitor_network():
    for conn in psutil.net_connections(kind='inet'):
        try:
            if conn.status == 'ESTABLISHED' and conn.raddr:
                ip, port = conn.raddr
                if port not in COMMON_PORTS:
                    logging.warning(f"🌐 Unusual connection: {ip}:{port}")
        except:
            continue

# ------------------------------------
# PROCESS SURGE MONITOR
# ------------------------------------
prev_count = len(psutil.pids())

def detect_process_surge():
    global prev_count
    current = len(psutil.pids())
    if current > prev_count + PROCESS_SURGE_THRESHOLD:
        logging.warning("🐍 Sudden process surge — potential malware or worm.")
    prev_count = current

# ------------------------------------
# KILL BAD PROCESSES (COMMENTED OUT)
# ------------------------------------
def kill_processes(pids):
    for pid in set(pids):
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            logging.info(f"🔪 Terminated: {proc.name()} (PID {pid})")
        except Exception as e:
            logging.error(f"Failed to kill PID {pid}: {e}")

# ------------------------------------
# MAIN LOOP
# ------------------------------------
def run_edr():
    logging.info("🚀 EDR Lite 2.0 Started.")
    event_handler = EDRFileEventHandler()
    observer = Observer()
    observer.schedule(event_handler, path=WATCH_PATH, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(5)
            bad_pids = detect_behavior()
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    run_edr()
