import csv, time, os, sys, subprocess, requests, traceback, gc, re, termios, tty, select, shlex
from datetime import datetime
from itertools import cycle
from subprocess import Popen, PIPE
from collections import deque, defaultdict
from scapy.all import *
#from binascii import hexlify
from pathlib import Path

from colorama import init, Fore, Style
init() # Init colorama

#################################################################
#########################   VAriables  ##########################
#################################################################

DEBUG_FILE_PATH = "debug.txt" # If there are some errors, it will appears here
Karma_list = set()
karma = "no"

log_buffer = deque(maxlen=40) # Attack logs output 40 lines max
process_attack = None

sta_mac = "02:00:00:9E:1C:69"   # Fake mac station (blacklist output)

attackmode = "no"

ap_channels = {}
bssid_color_map = {} # Store the list of colors assigned to the BSSIDs
used_colors = [] # Store a list of colors that have already been assigned
tsharked = "" # Check tshark installation for WPS checkin
last_wps_check    = time.monotonic() # Refresh wps every X read_and_display_csv cycle

mapped = "no"
airmon = "no"
TXpower = "no"

errors_detected = False

oldchannel = ""


#################################################################
#######################   Errors & debug  #######################
#################################################################

def init_debug_file():
    """Init debug with date of today"""
    try:
        with open(DEBUG_FILE_PATH, "a") as f:
            date_now = datetime.now().strftime("%Y-%m-%d")
            f.write(f"\n\n" + '-' * 20 + f" {date_now} " + '-' * 20 + "\n")
    except:
        pass    

def log_debug(message, include_traceback=False):
    """Debug with hour and trackeback."""
    try:
        with open(DEBUG_FILE_PATH, "a") as f:
            time_now = datetime.now().strftime("%H:%M:%S")
            f.write(f"[{time_now}] {message}\n")
            
            if include_traceback: # Add Traceback if needed
                f.write(traceback.format_exc())
                f.write("\n")
    except:
        pass
        

#################################################################
#########################   Check & co  #########################
#################################################################

def clear_console():
    """Clear the screen for continuous updates"""
    os.system('clear')
    
def check_and_delete_output_file(file_path_csv, file_path_cap, script_path, save_airodump):
    """cache files check and clean"""
    try:
        if os.path.exists(script_path):
            os.remove(script_path)
            print(f"{Fore.CYAN}[INFO] {Style.RESET_ALL}The file '{script_path}' has been deleted")
            log_debug(f"[INFO] The file '{script_path}' has been deleted", include_traceback=False)
    except PermissionError as e:
        print(f"{Fore.RED}[!] Couldn't delete '{script_path}' : {e}")
        log_debug(f"Couldn't delete '{script_path}'", include_traceback=False)

    try:
        if os.path.exists("airgraph.sh"):
            os.remove("airgraph.sh")
            print(f"{Fore.CYAN}[INFO] {Style.RESET_ALL}The file 'airgraph.sh' has been deleted")
            log_debug(f"[INFO] The file 'airgraph.sh' has been deleted", include_traceback=False)
    except PermissionError as e:
        print(f"{Fore.RED}[!] Couldn't delete airgraph.sh : {e}")
        log_debug(f"Couldn't delete airgraph.sh : {e}", include_traceback=False)

    try:
        if os.path.exists("/tmp/wps.txt"):
            os.remove("/tmp/wps.txt")
            print(f"{Fore.CYAN}[INFO] {Style.RESET_ALL}The file '/tmp/wps.txt' has been deleted")
            log_debug(f"[INFO] The file '/tmp/wps.txt' has been deleted", include_traceback=False)
    except PermissionError as e:
        print(f"{Fore.RED}[!] Couldn't delete /tmp/wps.txt : {e}")
        log_debug(f"Couldn't delete /tmp/wps.txt : {e}", include_traceback=False)

    try:
        if save_airodump == "yes":
            print(f"{Fore.CYAN}[INFO] {Style.RESET_ALL}Airodump-ng file formats are saved and located in the '/tmp' directory. Make sure to move or save them before relaunching the script")
        
        if save_airodump == "yes":
            pass
        else:    
            if os.path.exists(file_path_csv):
                os.remove(file_path_csv)
                print(f"{Fore.CYAN}[INFO] {Style.RESET_ALL}The file '{file_path_csv}' has been deleted")
                log_debug(f"[INFO] The file '{file_path_csv}' has been deleted", include_traceback=False)
    except PermissionError as e:
        print(f"{Fore.RED}[!] Couldn't delete '{file_path_csv}' : {e}")
        log_debug(f"Couldn't delete '{file_path_csv}'", include_traceback=False)

    try:
        if save_airodump == "yes":
            pass
        else:    
            if os.path.exists(file_path_cap):
                os.remove(file_path_cap)
                print(f"{Fore.CYAN}[INFO] {Style.RESET_ALL}The file '{file_path_cap}' has been deleted")
                log_debug(f"[INFO] The file '{file_path_cap}' has been deleted", include_traceback=False)
    except PermissionError as e:
        print(f"{Fore.RED}[!] Couldn't delete '{file_path_cap}' : {e}")
        log_debug(f"Couldn't delete '{file_path_cap}'", include_traceback=False)

    try:
        if save_airodump == "yes":
            pass
        else:    
            if os.path.exists("/tmp/output-01.kismet.csv"):
                os.remove("/tmp/output-01.kismet.csv")
                print(f"{Fore.CYAN}[INFO] {Style.RESET_ALL}The file '/tmp/output-01.kismet.csv' has been deleted")
                log_debug(f"[INFO] The file '/tmp/output-01.kismet.csv' has been deleted", include_traceback=False)
    except PermissionError as e:
        print(f"{Fore.RED}[!] Couldn't delete '/tmp/output-01.kismet.csv' (--get option feature trigger) : {e}")
        log_debug(f"Couldn't delete '/tmp/output-01.kismet.csv' (--get option feature trigger)", include_traceback=False)

    try:
        if save_airodump == "yes":
            pass
        else:    
            if os.path.exists("/tmp/output-01.kismet.netxml"):
                os.remove("/tmp/output-01.kismet.netxml")
                print(f"{Fore.CYAN}[INFO] {Style.RESET_ALL}The file '/tmp/output-01.kismet.netxml' has been deleted")
                log_debug(f"[INFO] The file '/tmp/output-01.kismet.netxml' has been deleted", include_traceback=False)
    except PermissionError as e:
        print(f"{Fore.RED}[!] Couldn't delete '/tmp/output-01.kismet.netxml' (--get option feature trigger) : {e}")
        log_debug(f"Couldn't delete '/tmp/output-01.kismet.netxml' (--get option feature trigger)", include_traceback=False)

    try:
        if save_airodump == "yes":
            pass
        else:    
            if os.path.exists("/tmp/output-01.log.csv"):
                os.remove("/tmp/output-01.log.csv")
                print(f"{Fore.CYAN}[INFO] {Style.RESET_ALL}The file '/tmp/output-01.log.csv' has been deleted")
                log_debug(f"[INFO] The file '/tmp/output-01.log.csv' has been deleted", include_traceback=False)
    except PermissionError as e:
        print(f"{Fore.RED}[!] Couldn't delete '/tmp/output-01.log.csv' (--get option feature trigger) : {e}")
        log_debug(f"Couldn't delete '/tmp/output-01.log.csv' (--get option feature trigger)", include_traceback=False)

def check_and_install_tools(tools):
    """
    Vérifie si les outils nécessaires sont installés, et les installe s'ils ne le sont pas.
    
    :param tools: Liste des noms des outils à vérifier.
    """
    for tool in tools:
        try:
            # Checking aviability
            subprocess.run(["which", tool], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except subprocess.CalledProcessError:
            print(f"{Fore.RED}[!] {Style.RESET_ALL}{tool} isn't installed")
            install = input(f"{Fore.CYAN}[?] {Style.RESET_ALL}Install {tool} ? (y/n) : ").strip().lower()
            if install in ['y', 'yes']:
                try:
                    print(f"{Fore.GREEN}[+] {Style.RESET_ALL}Installing {tool}...")
                    subprocess.run(["sudo", "apt-get", "install", "-y", tool], check=True)
                    print(f"{Fore.GREEN}[+] {Style.RESET_ALL}{tool} has been successfully installed")
                except subprocess.CalledProcessError as e:
                    log_debug(f"{e}", include_traceback=True)
            else:
                print(f"{Fore.RED}[!] Some functionalities may not work properly. Skipping ....")
                log_debug(f"[!] {tool} isn't installed. Some functionalities may not work properly. Skipping ....", include_traceback=False)
        

#################################################################
######################### Bash programs #########################
#################################################################

def airodump(script_path, channel, interface, save_airodump, airmon, attackmode):
    save_airodump2 = ""
    
    if save_airodump == "yes":
        save_airodump2 = ""
    else:
        save_airodump2 = " --output-format csv,cap"

    if attackmode == "yes":
        if "-f" not in channel:
            channel = channel + " -f 60000"

    # Step 1 : create bash file
    bash_script = f"""#!/bin/bash
    airodump-ng {interface} --write /tmp/output{save_airodump2} --write-interval 2 --background 1 {channel}
    """
    
    if airmon == "yes": # add airmon-ng check kill to script
        bash_script = f"""#!/bin/bash
        airmon-ng check kill
        airodump-ng {interface} --write /tmp/output{save_airodump2} --write-interval 2 --background 1 {channel}
        """    
    
    print(f"{Fore.YELLOW}[!] {Style.RESET_ALL}Launching the following script :")
    print(f"{Fore.GREEN}------------------------------------------------------------------------{Style.RESET_ALL}")
    print(bash_script)
    print(f"{Fore.GREEN}------------------------------------------------------------------------{Style.RESET_ALL}")

    try:
        with open(script_path, 'w') as f:
            f.write(bash_script)

        # Step 2 : chmod bash file
        os.chmod(script_path, 0o755)
        process = subprocess.Popen([script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:
        log_debug(f"{e}", include_traceback=True)


def airgraph():
    base_directory = os.getcwd()
    script_name = "airgraph.sh"
    script_path = os.path.join(base_directory, script_name)
    
    # Step 1 : create bash file
    bash_script = f"""#!/bin/bash
    airgraph-ng -o CAPR_png -i /tmp/output-01.csv -g CAPR
    airgraph-ng -o CPG_png -i /tmp/output-01.csv -g CPG
    """

    try:
        with open(script_path, 'w') as f:
            f.write(bash_script)

        # Step 2 : chmod bash file
        os.chmod(script_path, 0o755)
        process = subprocess.run([f"./{script_name}"], check=True, cwd=base_directory, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:
        log_debug(f"{e}", include_traceback=True)


def help_airodump():
    infos = f'''
  {Fore.GREEN}------------------------------------------------------------------------{Style.RESET_ALL}
  Script by {Fore.RED}raphaelthief 
  {Fore.GREEN}------------------------------------------------------------------------{Style.RESET_ALL}
  Airodump background tool credits to :
  Airodump-ng 1.7  - (C) 2006-2022 Thomas d'Otreppe  
  https://www.aircrack-ng.org
  {Fore.GREEN}------------------------------------------------------------------------{Style.RESET_ALL}

  Filter options:
      --encrypt   <suite>   : Filter APs by cipher suite,
                              you can pass multiple --encrypt options
      --netmask <netmask>   : Filter APs by mask
      --bssid     <bssid>   : Filter APs by BSSID,
                              you can pass multiple --bssid options
      --essid     <essid>   : Filter APs by ESSID,
                              you can pass multiple --essid options
      --essid-regex <regex> : Filter APs by ESSID using a regular
                              expression
      --min-packets   <int> : Minimum AP packets recv'd before
                              displaying it (default: 2)
      --min-power     <int> : Filter out APs with PWR less than
                              the specified value (default: -120)
      --min-rxq       <int> : Filter out APs with RXQ less than
                              the specified value (default: 0)
                              Requires --channel (or -c) or -C
      -a                    : Filter out unassociated stations
      -z                    : Filter out associated stations

  By default, airodump-ng hops on 2.4GHz channels.
  You can make it capture on other/specific channel(s) by using:
      --ht20                : Set channel to HT20 (802.11n)
      --ht40-               : Set channel to HT40- (802.11n)
      --ht40+               : Set channel to HT40+ (802.11n)
      --channel <channels>  : Capture on specific channels
      --ignore-other-chans  : Filter out other channels
                              Requires --channel (or -c)
      --band <abg>          : Band on which airodump-ng should hop
      -C    <frequencies>   : Uses these frequencies in MHz to hop
      --cswitch  <method>   : Set channel switching method
                    0       : FIFO (default)
                    1       : Round Robin
                    2       : Hop on last

      --help                : Displays this usage screen
  {Fore.GREEN}------------------------------------------------------------------------{Style.RESET_ALL}

  Extra settings (script settings):
      --get    : Get all airodump-ng outputs without deleting them by closing the script (located in /tmp directory)
      --attack : Launch deauth attacks with formed packets with scapy (airodump-ng args '-f' set to 60000)
                - PMKID attacks
                    - Assoc PMKID
                    - Assoc FT PMKID
                    - Probe PMKID
                - Deauth attacks
                    - AP to Clients (code 7)
                    - Client to AP (code 7)
                    -  Deauth AP broadcast (code 7)
                --> Extra commands with --attack mod :
                    --scan-rounds : Number of scan cycles to perform (default: 3 rounds)
                    --dwell-time  : Time (in seconds) to stay on each channel (default: 3s)
                    --cswitch     : Canal switch methods (0: FIFO, 1: Round Robin, 2: Hop on last). FIFO by default
                    - If no channel (-c or --channel) is provided, the attack will run on channels 1, 6, 11 by default
      --karma  : Collect all probe ESSID from clients and show them all when closing    
  {Fore.GREEN}------------------------------------------------------------------------{Style.RESET_ALL}
  
  Internal functionnement:
      airodump-ng <selected interface> --write /tmp/output --output-format csv,cap --write-interval 2 --background 1 <your commands inputs>
      manufacturer comes from oui file
      wps infos comes from the extract .cap file made by airodump-ng
      Last seen AP and Clients before timeout : 60s

  Aigraph functionnement (wireless mapping):
      airgraph-ng -o CAPR_png -i /tmp/output-01.csv -g CAPR
      airgraph-ng -o CPG_png -i /tmp/output-01.csv -g CPG

  Karma functionnement:
      Just rewrite all probed ESSID from Clients

  Attack functionnement:
      Use Scapy lib to perform PMKID & Deauth attacks
      All deauth are set to reason code 7
      Various PMKID attacks supported
      Attack only 1 time each targets (AP & clients)
      PMKID probes set to null bytes (0x00 * 16)
      Deatuh packets send for each targets : x5
      PMKID packets send for each targets  : x3

  Press [SPACE] to pause & resume the output. Airodump-ng will still cap in background    
'''    
    print(infos)


#################################################################
######################### WPS functions #########################
#################################################################

def check_wps(bssid):
    try:
        wpsvalue = ""
        bssid = bssid.lower()
        if os.path.exists("/tmp/wps.txt"):
            with open("/tmp/wps.txt", 'r') as file:
                for line in file:
                    if bssid in line:
                        data = line.strip().split(',')
                        result_parts = []

                        # Check AP Setup Lock (0x01 = Yes, other = No)
                        if len(data) > 1 and data[2]:
                            if data[1] == "0x01":
                                return "[Locked]"
                                
                        # Check Default Settings Status
                        if len(data) > 2 and data[2]:
                            if data[2] != "0x02":
                                result_parts.append("[Unset]")
                                

                        if len(data) > 3 and data[3]: 
                            try:
                                # Convert the field to an integer to analyze the bits
                                config_methods = int(data[3], 16)
                                config_parts = []

                                # Masks for each method
                                method_mapping = {
                                    0x0001: "USB",
                                    0x0002: "ETH",
                                    0x0004: "LAB",
                                    0x0008: "DIS",
                                    0x0010: "VRDIS",
                                    0x0020: "PHYDIS",
                                    0x0040: "ExtNFC",
                                    0x0080: "IntNFC",
                                    0x0100: "NFC",
                                    0x0200: "PUSH",
                                    0x0400: "VRPUSH",
                                    0x0800: "PhyPUSH",
                                    0x1000: "KEYPAD"
                                }

                                # Check which bits are enabled
                                for mask, name in method_mapping.items():
                                    if config_methods & mask:
                                        config_parts.append(name)

                                # Add the decoded results
                                if config_parts:
                                    result_parts.append(",".join(config_parts))
                            except Exception as e:
                                log_debug(f"{e}", include_traceback=True)

                        if len(data) > 4 and data[4]:
                            wps_version = data[4]
                            if wps_version == "0x10":
                                wpsvalue = "1.0"
                            elif wps_version == "0x11":
                                wpsvalue = "1.1"
                            elif wps_version == "0x20":
                                wpsvalue = "2.0"
                        
                        # Additional check: Vendor Extension (0x1049)
                        if len(data) > 5 and data[5]:  # L'extension fournisseur est dans data[5]
                            vendor_extension = data[5]
                            if vendor_extension.startswith("00372a"):  # Check Wi-Fi Alliance signature
                                extension_data = vendor_extension[6:]  # Skip the signature
                                while extension_data:
                                    tag = int(extension_data[:2], 16)  # Read the tag
                                    length = int(extension_data[2:4], 16)  # Read the length
                                    value = extension_data[4:4 + length * 2]  # Extract value
                                    if tag == 0x00:  # Check for Version2 in Vendor Extension
                                        if len(value) >= 2:
                                            version2 = value[:2]
                                            if version2 == "10":
                                                wpsvalue = "1.0"
                                            elif version2 == "20":
                                                wpsvalue = "2.0"
                                        break
                                    extension_data = extension_data[4 + length * 2:]  # Move to the next entry

                        if wpsvalue != "":
                            result_parts.insert(0, wpsvalue) # add it at the first position of result_parts

                        return ' '.join(result_parts) if result_parts else "/"
        else:            
            return "/"
    except Exception as e:
        log_debug(f"{e}", include_traceback=True)
        return "/"


def check_wps_update():
    cmd = [
        'tshark',
        '-r', '/tmp/output-01.cap',  # Path to cap file
        '-n',  # Don't resolve addresses
        '-Y', 'wps.wifi_protected_setup_state',
        '-T', 'fields',  # Only output certain fields
        '-e', 'wlan.ta',  # BSSID
        '-e', 'wps.ap_setup_locked',  # Locked status
        
        
        '-e', 'wps.wifi_protected_setup_state',  # Default settings status
        '-e', 'wps.config_methods',  # WPS configuration methods
        '-e', 'wps.version',  # WPS version
        '-e', 'wps.vendor_extension',  # WPS version from vendor
        '-E', 'separator=,'  # CSV format
    ]
    
    #cmd_sort = ['sort', '-u'] # tshark_command | sort -u
    
    output_file = '/tmp/wps.txt'  # Output file path
    
    try:
        # Check if the cap file exists and has data
        if os.path.exists("/tmp/output-01.cap") and os.path.getsize("/tmp/output-01.cap") > 0:
            # Try to execute tshark and capture any errors
            proc_tshark = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            #proc_sort = subprocess.Popen(cmd_sort, stdin=proc_tshark.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            # Ensure the pipe doesn't block
            #proc_tshark.stdout.close()
            stdout, stderr = proc_tshark.communicate()
            #stdout, stderr = proc_sort.communicate()

            if proc_tshark.returncode == 0:
                # If tshark executes successfully, write output to the file
                with open(output_file, 'w') as file:
                    file.write(stdout.decode())
                
    except Exception as e:
        log_debug(f"{e}", include_traceback=False) # There use to to be a lot of errors it's normal (sync between airodump-ng cap file and the tool) 
        pass


#################################################################
######################### Format stuffs #########################
#################################################################

def get_signal_color(power):
    """
    Returns a color based on the signal strength
    :param power: The signal strength (in dBm, negative integer)
    :return: A Colorama color
    """
    try:
        power = int(power)
        if power == -1:  # Specific case for value -1
            return Fore.RED  # Very weak or not aviable
        elif power >= -50:
            return Fore.GREEN  # Very strong
        elif -70 <= power < -50:
            return Fore.YELLOW  # Medium
        else:
            return Fore.RED  # Weak
    except ValueError:
        return Fore.WHITE  # Default


def format_text(text, width):
    """Format a string to adhere to a specific width"""
    try:
        
        if text is None:
            text = ""
        
        if len(text) > width:
            return text[:width - 3] + "..."  # Truncate and add "..."
        return text.ljust(width)  
    except Exception as e:
        log_debug(f"{e}", include_traceback=True)


def get_color_palette():
    """Return a cycle of colors for matching BSSIDs."""
    try:
        colors = [
            '\033[38;5;1m',   # Color_1: Red
            '\033[38;5;2m',   # Color_2: Green
            '\033[38;5;3m',   # Color_3: Yellow (dark)
            '\033[38;5;4m',   # Color_4: Blue
            '\033[38;5;5m',   # Color_5: Magenta
            '\033[38;5;6m',   # Color_6: Cyan
            '\033[38;5;13m',  # Color_13: Magenta (bright)
            '\033[38;5;14m',  # Color_14: Bright Cyan
            '\033[38;5;21m',  # Color_21: Royal Blue
            '\033[38;5;46m',  # Color_46: Lime Green
            '\033[38;5;225m', # Color_225: Pale Pink
            '\033[38;5;201m', # Color_201: Fuchsia
            '\033[38;5;213m', # Color_213: Bright Pink
            '\033[38;5;101m', # Color_101: Rosy Red
            '\033[38;5;226m', # Color_226: Bright Yellow
        ] # Feel free to add more colors here
        
        # Reinitialise colors if already all used
        if len(used_colors) >= len(colors):
            used_colors.clear()  # Reinit

        # Make cycle colors
        return cycle([color for color in colors if color not in used_colors])
    except Exception as e:
        log_debug(f"{e}", include_traceback=True)



#################################################################
#########################  Manufacturer #########################
#################################################################

def load_manufacturer_data(oui_file):
    """Load and return manufacturer from oui db"""
    manufacturer_map = {}
    try:
        with open(oui_file, "r", encoding="utf-8") as file:
            for line in file:
                if "(hex)" in line:
                    parts = line.split("(hex)")
                    if len(parts) == 2:
                        oui_hex = parts[0].strip().replace("-", ":").upper()  # Format XX:XX:XX
                        manufacturer = parts[1].strip()
                        manufacturer_map[oui_hex] = manufacturer
    except FileNotFoundError:
        print(f"Fichier OUI non trouvé : {oui_file}")
    except Exception as e:
        log_debug(f"{e}", include_traceback=False)
        print(f"Erreur lors du chargement des données OUI : {e}")
    return manufacturer_map


def get_manufacturer(mac, manufacturer_map):
    """Return manufacturer MAC adress."""
    try:
        oui = ":".join(mac.upper().split(":")[:3])  # Take 3 first octets
        return manufacturer_map.get(oui, "Unknow")
    except Exception as e:    
        log_debug(f"{e}", include_traceback=True)
        return "Unknow"


#################################################################
########################### TX Power ############################
#################################################################

def set_txpower(interface: str, dbm: int) -> bool:
    """Set TX Power (dBm → centi-dBm). Return True if success"""
    try:
        value = str(dbm * 100)  # Ex: 30 dBm → "3000"
        subprocess.run(
            ["sudo", "iw", "dev", interface, "set", "txpower", "fixed", value],
            check=True, capture_output=True
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[!] Couldn't set TX Power : " + (e.stderr or e.stdout).decode() if isinstance(e.stderr, bytes) else e.stderr)
        log_debug("[INFO] Couldn't set TX Power : " + (e.stderr or e.stdout).decode() if isinstance(e.stderr, bytes) else e.stderr, include_traceback=False)
        return False

def get_txpower(interface: str) -> float:
    """Actual TX Power (dBm)."""
    try:
        result = subprocess.check_output(["iw", "dev", interface, "info"], text=True)
        match = re.search(r"txpower\s+([\d.]+)\s+dBm", result)
        return float(match.group(1)) if match else -1.0
    except subprocess.CalledProcessError:
        return -1.0


#################################################################
############################ --save #############################
#################################################################

def save_to_csv(file_name, headers, data):
    """
    Save the given data into a CSV file.
    :param file_name: Name of the output file.
    :param headers: A list of column headers.
    :param data: A list of rows to be written to the CSV file.
    """
    try:
        with open(file_name, mode='w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            if headers:
                writer.writerow(headers)
            writer.writerows(data)
        print(f"Data saved to {file_name}")
    except Exception as e:
        print(f"{Fore.RED}[!] {Style.RESET_ALL}Failed to save data to {file_name}: {e}")
        log_debug(f"{e}", include_traceback=True)


#################################################################
######################### Display infos #########################
#################################################################

def stream_output(process):
    for line in iter(process.stdout.readline, b''):
        decoded = line.decode(errors="replace").rstrip()
        log_buffer.append(decoded)


def analyse_handshakes(cap_file: str) -> dict[str, dict]:
    """
    Check .cap and for each BSSID :
      {
        "pmkid"         : True/False,
        "eapol_counts"  : {1: n1, 2: n2, 3: n3, 4: n4},
        "eapol_total"   : somme des n,
        "eapol_complete": True/False (at least 1x M1,M2,M3,M4),
        "crackable"     : pmkid or eapol_complete
      }
    """

    # --- A) PMKID ----------------------------------------------------------
    cmd_pmkid = (
        f"tshark -r '{cap_file}' "
        "-Y 'wlan.rsn.ie.pmkid and wlan.rsn.ie.pmkid != 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00' "
        "-T fields -e wlan.bssid | sort -u"
    )
    pmkid_out = subprocess.run(
        cmd_pmkid, shell=True,
        capture_output=True, text=True
    ).stdout

    # --- B) EAPOL : msgnr ------------------------------------
    cmd_eapol = (
        f"tshark -r '{cap_file}' -Y eapol "
        "-T fields -e wlan.bssid -e wlan_rsna_eapol.keydes.msgnr"
    )
    run_eapol = subprocess.run(
        cmd_eapol, shell=True,
        capture_output=True, text=True
    )
    eapol_out = run_eapol.stdout

    info: dict[str, dict] = defaultdict(lambda: {
        "pmkid": False,
        "eapol_counts": defaultdict(int)
    })

    # -- PMKID
    for bssid in pmkid_out.splitlines():
        bssid = bssid.strip().lower()
        if bssid:
            info[bssid]["pmkid"] = True

    # -- Count M1‑M4 if msgnr aviable
    if eapol_out:
        for line in eapol_out.splitlines():
            try:
                bssid, msg = line.split('\t')
                m = int(msg)
                if 1 <= m <= 4:
                    info[bssid.lower()]["eapol_counts"][m] += 1
            except ValueError:
                continue
    else:
        # --- Fallback : key_info --------------------------
        cmd_eapol = (
            f"tshark -r '{cap_file}' -Y eapol "
            "-T fields -e wlan.bssid -e wlan_rsna_eapol.keydes.key_info"
        )
        eapol_out = subprocess.run(
            cmd_eapol, shell=True,
            capture_output=True, text=True
        ).stdout

        def msg_from_keyinfo(ki: int) -> int | None:
            # Bits (little‑endian) : 0x40 Install / 0x80 ACK / 0x100 MIC
            install = bool(ki & 0x0040)
            ack     = bool(ki & 0x0080)
            mic     = bool(ki & 0x0100)
            if  ack and not mic and not install: return 1   # M1
            if not ack and     mic and not install: return 2   # M2
            if  ack and     mic and     install: return 3   # M3
            if not ack and     mic and not install: return 4   # M4 (Secure bit)
            return None

        for line in eapol_out.splitlines():
            try:
                bssid, ki = line.split('\t')
                m = msg_from_keyinfo(int(ki, 0))
                if m:
                    info[bssid.lower()]["eapol_counts"][m] += 1
            except ValueError:
                continue

    for bssid, d in info.items():
        counts = d["eapol_counts"]
        has_M1M2 = counts.get(1, 0) > 0 and counts.get(2, 0) > 0
        has_M2M3 = counts.get(2, 0) > 0 and counts.get(3, 0) > 0

        d["eapol_minimal"] = has_M1M2 or has_M2M3
        if has_M1M2:
            d["eapol_pair"] = "M1+M2"
        elif has_M2M3:
            d["eapol_pair"] = "M2+M3"
        else:
            d["eapol_pair"] = None

    # -- Final output
    for d in info.values():
        counts = d["eapol_counts"]
        d["eapol_total"]    = sum(counts.values())
        d["eapol_complete"] = all(counts.get(m, 0) > 0 for m in (1, 2, 3, 4))
        #d["crackable"]      = d["pmkid"] or d["eapol_complete"]
        d["crackable"]      = d["pmkid"] or d.get("eapol_minimal", False)

    return info

def get_current_channel(interface):
    try:
        output = subprocess.check_output(["iw", "dev", interface, "info"]).decode()
        match = re.search(r"channel\s+(\d+)", output)
        if match:
            return int(match.group(1))
    except Exception as e:
        log_debug(f"[INFO] Channel display error : {e}", include_traceback=True)
    return "Unknow"

def read_and_display_csv(file_path, interface, channel, mapped, TXpower, file_path_cap, tsharked, save_airodump, timeout_sec):
    """Display CSV data from airodump-ng with unique colors for each matched BSSID."""
    global last_wps_check, errors_detected, oldchannel, karma, process_attack,attackmode
    
    # Pause & Resume stuff 
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    tty.setcbreak(fd)
    paused = False

    while True:
        # Pause & Resume stuff 
        r, _, _ = select.select([sys.stdin], [], [], 0)
        if r:
            ch = sys.stdin.read(1)
            if ch == ' ':
                paused = not paused
                print(f"\n{Fore.CYAN}[PAUSED]" if paused else f"{Fore.CYAN}[RESUME]")

        # Get current channel listening
        current_channel = get_current_channel(interface)

        if not paused:
            #time.sleep(3)  # Refresh every 3s
            try:
                tsharkinfos = " |"
                mappedinfos = "Network mapping disabled"
                TXpowerinfos = "(20-22db)"

                handshake_info = analyse_handshakes('/tmp/output-01.cap')
                #already_cracked = {b for b, d in handshake_info.items() if d.get("crackable")}

                nb_crackable   = sum(1 for v in handshake_info.values() if v["crackable"])
                nb_pmkid       = sum(1 for v in handshake_info.values() if v["pmkid"])
                nb_4way        = sum(1 for v in handshake_info.values() if v["eapol_complete"])
                nb_minimal     = sum(1 for v in handshake_info.values() if v.get("eapol_minimal", False))

                try:
                    manufacturer_map = load_manufacturer_data("oui.txt") # Manufacturer datas from https://standards-oui.ieee.org/oui/oui.txt
                except:
                    pass
                    
                if tsharked == "no":
                    tsharkinfos = " | tshark not installed - no WPS infos displayed |"
                
                if mapped == "yes":
                    mappedinfos = "Network mapping enabled at the end of the scan"
                else:
                    mappedinfos = "Network mapping disabled"
                
                bandz = "2.4GHz band" if channel == "" else f"command {channel}"
                
                if TXpower == "yes":
                    TXpowerinfos = "(30db)"

                if karma == "yes":
                    karmatrigger = f"| {Fore.RED}[!] Karma sniffing"
                else:
                    karmatrigger = ""

                if attackmode == "yes":
                    attacktrigger = f"| {Fore.RED}[!] Attack mode enabled"
                else:
                    attacktrigger = ""

                try:
                    with open(file_path, mode='r', newline='', encoding='iso-8859-1') as csvfile:
                        reader = csv.reader(csvfile)
                        data = list(reader)

                        # Separate the sections of the APs and the clients
                        ap_data = []
                        station_data = []

                        is_station_section = False
                        for row in data:
                            if row and row[0].startswith('Station MAC'):
                                is_station_section = True
                                continue  # Ignore the header of the clients
                            
                            if not is_station_section:
                                ap_data.append(row)
                            else:
                                station_data.append(row)

                        # Extract the BSSIDs from the APs and the clients
                        ap_bssids = {row[0].strip() for row in ap_data if len(row) > 0 and row[0].strip()}
                        #client_bssids = {row[5].strip() for row in station_data if len(row) > 0 and row[5].strip()}
                        client_bssids = {row[5].strip() for row in station_data if len(row) > 5 and row[5].strip()}

                        # Clear unused used_colors and bssid_color_map
                        for bssid, color in list(bssid_color_map.items()):
                            if bssid not in ap_bssids and bssid not in client_bssids:
                                used_colors.remove(color)  
                                del bssid_color_map[bssid]  # Clear inactives BSSID colors attribued

                        # Create a color palette for the matches
                        color_palette = get_color_palette()
                        bssids_with_ignored_client = set()

                        for row in station_data:
                            if len(row) > 5:
                                client_mac = row[0].strip().lower()
                                associated_bssid = row[5].strip().lower()
                                if client_mac == sta_mac.lower() and associated_bssid:
                                    bssids_with_ignored_client.add(associated_bssid)

                        # Assign a unique color to the BSSIDs that appear in both the APs and the clients
                        for bssid in ap_bssids & client_bssids:
                            bssid_lc = bssid.lower()
                            if bssid_lc in bssids_with_ignored_client:
                                continue  # Skip coloring this BSSID
                            if bssid not in bssid_color_map: # Assign a color if it has not been assigned
                                try:
                                    color = next(color_palette)
                                except StopIteration: # Restart iteration if all colors where used
                                    color_palette = get_color_palette()
                                    color = next(color_palette)
                                bssid_color_map[bssid] = color
                                used_colors.append(color) # Set used colors

                        # Show data after clearing the console
                        clear_console()
                        
                        # AP's
                        print(f"{Fore.YELLOW}[!] Listening on {interface} [Channel : {Fore.RED}{current_channel}{Fore.YELLOW}] {TXpowerinfos} on {bandz} (AP's & Clients timeout : {timeout_sec} seconds){tsharkinfos} {mappedinfos} | Press [SPACE] to pause & resume {attacktrigger} {Fore.YELLOW}{karmatrigger}")
                        print(
                            f"{Fore.YELLOW}[!] Captured handshakes : "
                            f"{Fore.RED}{nb_crackable}{Fore.YELLOW} "
                            f"(PMKID : {nb_pmkid}  4-way : {nb_4way}  Minimal (M1+M2/M2+M3) : {nb_minimal})\n"
                        )
                        print(f"{Fore.CYAN}==== Access Point (AP) ===={Style.RESET_ALL}")
                        print(f"{'BSSID':<20}{'Channel':<10}{'# Beacons':<15}{'Privacy':<15}{'Cipher':<15}{'Authentication':<17}{'Power':<10}{'WPS':<20}{'ESSID':<20}{'Manufacturer'}")
                        print('-' * 155)

                        for row in ap_data:
                            if len(row) > 1 and row[2].strip() != "Last time seen":
                                try:
                                    format_str = "%Y-%m-%d %H:%M:%S"  # format
                                    date_obj = datetime.strptime(row[2].strip(), format_str)
                                    current_time = datetime.now()
                                    time_difference = current_time - date_obj
                                    if time_difference.total_seconds() > timeout_sec:  # timeout 60s --> realtime live clients default
                                        continue
                                    else:
                                        power_color = get_signal_color(row[8])  # Color based on the signal strength
                                        bssid = row[0].strip()
                                        bssid1 = row[0].strip().lower()
                                        
                                        channel_hope = row[3].strip()
                                        ap_channels[bssid1] = channel_hope

                                        manufacturer = get_manufacturer(bssid, manufacturer_map)                            
                                        bssid_color = bssid_color_map.get(bssid, "")  # Get unique color if matched
                                        
                                        security = row[5].strip()
                                        if security in ['OPN', 'WEP']:
                                            security_color = Fore.GREEN
                                        else:
                                            security_color = bssid_color

                                        MGT = row[7].strip()
                                        if MGT == "MGT":
                                            MGT_color = Fore.RED
                                        else:
                                            MGT_color = bssid_color

                                        if tsharked == "no":
                                            wps_status = "/"
                                        else:
                                            try:
                                                wps_status = check_wps(bssid)
                                                if wps_status is None or wps_status.strip() == "": # Security check (:<value can't be a None value)
                                                    wps_status = "/"  # Default string value
                                            except Exception as e:
                                                wps_status = "/"
                                            
                                            if wps_status == "[Locked]":
                                                wps_color = Fore.RED
                                            else:
                                                wps_color = bssid_color

                                        h = handshake_info.get(bssid1, {})

                                        if not h:
                                            handshake_text = ""
                                        else:
                                            tags = []
                                            if h.get("pmkid"):
                                                tags.append("PMKID")
                                            if h.get("eapol_complete"):
                                                tags.append("4-way OK")

                                            counts = h.get("eapol_counts", {})
                                            if counts:
                                                msg_parts = []
                                                for m in (1, 2, 3, 4):
                                                    c = counts.get(m, 0)
                                                    if c:
                                                        msg_parts.append(f"M{m}×{c}")
                                                if msg_parts:
                                                    tags.append(" / ".join(msg_parts))

                                            handshake_text = (
                                                f"   {Fore.CYAN}***{Fore.RED}[{' | '.join(tags)}]"
                                                f"{Fore.CYAN}***{Style.RESET_ALL}"
                                            )

                                        print(f"{bssid_color}{bssid:<20}{row[3]:<10}{row[9]:<15}{security_color}{row[5]:<15}{bssid_color}{row[6]:<15}{MGT_color}{row[7]:<17}{power_color}{row[8]:<10}{Style.RESET_ALL}{wps_color}{format_text(wps_status, 20)}{Style.RESET_ALL}{bssid_color}{format_text(row[13], 20)}{manufacturer}{Style.RESET_ALL}{handshake_text:<25}")
                                        
                                except Exception as e:
                                    errors_detected = True
                                    log_debug(f"{e}", include_traceback=True)
                                    continue

                        # Clients 
                        print(f"\n{Fore.CYAN}==== Clients (Stations) ===={Style.RESET_ALL}")
                        print(f"{'Station MAC':<20}{'Manufacturer':<30}{'Power':<10}{'# Packets':<15}{'BSSID':<20}{'Probed ESSIDs'}")
                        print('-' * 109)
                        for row in station_data:
                            #if len(row) > 1 and row[2].strip() != "Last time seen":
                            if len(row) > 2 and row[2].strip() != "Last time seen":    
                                try:
                                    format_str = "%Y-%m-%d %H:%M:%S"  # format
                                    date_obj = datetime.strptime(row[2].strip(), format_str)
                                    current_time = datetime.now()
                                    time_difference = current_time - date_obj
                                    if time_difference.total_seconds() > timeout_sec:  # timeout 60 --> realtime live clients default
                                        continue
                                    else:
                                    
                                        station_mac = row[0].strip()
                                        manufacturer = get_manufacturer(station_mac, manufacturer_map)
                                        
                                        power_color = get_signal_color(row[3])  # Color based on the signal strength
                                        
                                        bssid = row[5].strip()  # Client associated BSSID
                                        bssid_color = bssid_color_map.get(bssid, "")  # Get unique color if matched
                                        
                                        station_mac1 = row[0].strip().lower()
                                        bssid1 = row[5].strip().lower()

                                        print(f"{bssid_color}{row[0]:<20}{format_text(manufacturer, 30)}{power_color}{row[3]:<10}{Style.RESET_ALL}{bssid_color}{row[4]:<15}{bssid:<20}{row[6]}{Style.RESET_ALL}")

                                        if karma == "yes":
                                            if len(row[6]) > 1:
                                                Karma_list.add(row[6])

                                except Exception as e:
                                    errors_detected = True
                                    log_debug(f"{e}", include_traceback=True)
                                    continue

                        oldchannel = current_channel
                        now = time.monotonic()
                            
                        if now - last_wps_check >= 4: # 4s
                            last_wps_check = now # reset wps timer
                            
                            if tsharked == "no":
                                pass
                            else:                     
                                check_wps_update()

                        if attackmode == "yes":
                            print(f"\n{Fore.YELLOW}[!] Attack logs{Style.RESET_ALL}")
                            print("\n".join(log_buffer))

                        # Free memory to avoid crash
                        ap_data.clear()
                        station_data.clear()
                        del ap_data, station_data

                    time.sleep(0.2) # Cooldown
                except IOError as e:
                    log_debug(f"{file_path} in use by airodump-ng :\n{e}", include_traceback=False)

            except FileNotFoundError:
                print(f"File {file_path} doesn't exist. Closing ...")
                log_debug(f"File {file_path} doesn't exist. Closing ...", include_traceback=False)
                sys.exit(0)
            except KeyboardInterrupt:
                script_path = '/tmp/airodumpscript.sh'
                file_path_csv = '/tmp/output-01.csv'
                file_path_cap = '/tmp/output-01.cap'
                print(f"\n{Fore.RED}[!] KeyboardInterrupt")

                if attackmode == "yes":
                    print(f"{Fore.YELLOW}[!] Closing attack script")
                    process_attack.kill() # Yes brutal...

                if mapped.lower() in ['y', 'yes']:
                    try:
                        print(f"{Fore.GREEN}[+] {Style.RESET_ALL}Launching airgraph.sh ...")
                        airgraph()
                    except Exception as e:
                        print(f"{Fore.RED}[!] airgraph.sh couldn't be launched :")                
                        print(e)
                        log_debug(f"{e}", include_traceback=False)
                
                if airmon == "yes":
                    try:    
                        print(f"{Fore.CYAN}[INFO] {Style.RESET_ALL}Stoping monitor mode")
                        result = subprocess.run(
                            ["sudo","airmon-ng","stop",interface],
                            check=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True  # Decode output char
                        )
                        print(f"{Fore.CYAN}[INFO] {Style.RESET_ALL}Restarting NetworkManager")
                        result = subprocess.run(
                            ["sudo","systemctl","restart","NetworkManager.service"],
                            check=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True  # Decode output char
                        )
                    except Exception as e:
                        print(f"{Fore.RED}[!] Couldn't restart NetworkManager :")                
                        print(e)
                        log_debug(f"{e}", include_traceback=False)

                check_and_delete_output_file(file_path_csv, file_path_cap, script_path, save_airodump)

                if TXpower == "yes":
                    print(f"{Fore.CYAN}[INFO] {Style.RESET_ALL}Command to restore TX-Power : {Fore.YELLOW}sudo iw dev <interface> set txpower fixed 2000{Style.RESET_ALL}")
                
                if karma == "yes":
                    print(f"{Fore.YELLOW}[!] Collected ESSID from karma sniffing{Style.RESET_ALL}")
                    for mot in sorted(Karma_list):
                        print(f"{Fore.GREEN}[*] {Style.RESET_ALL}{mot}")

                if errors_detected:
                    print(f"{Fore.RED}[ERROR] {Style.RESET_ALL}Check debug.txt")

                sys.exit(0)    

            finally:
                gc.collect() # Free memory to avoid crash


#################################################################
######################   SAnitarize args   ######################
#################################################################

def remove_args(input_str, args_to_remove):
    """
    input_str: str, full argument string (e.g. "--channel 1,6,11 --scan-rounds 3")
    args_to_remove: list of argument names to remove (e.g. ["--scan-rounds", "--dwell-time"])
    
    returns: cleaned argument string
    """
    tokens = shlex.split(input_str)
    cleaned = []
    skip_next = False

    for i, token in enumerate(tokens):
        if skip_next:
            skip_next = False
            continue

        if token in args_to_remove:
            skip_next = True  # skip this token and the next (the value)
        else:
            cleaned.append(token)

    return " ".join(cleaned)

def parse_args_to_dict(arg_str):
    tokens = shlex.split(arg_str)
    args_dict = {}
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token.startswith("-"):
            # Next value if not flag
            if i+1 < len(tokens) and not tokens[i+1].startswith("-"):
                args_dict[token] = tokens[i+1]
                i += 2
            else:
                args_dict[token] = True
                i += 1
        else:
            i += 1
    return args_dict


#################################################################
#########################   Launching   #########################
#################################################################

def main():
    global errors_detected, airmon, TXpower, mapped, karma, process_attack,attackmode
    
    init_debug_file() # Launch debugger
    save_airodump = ""

    try:
        # Temp files location
        script_path = '/tmp/airodumpscript.sh'
        file_path_csv = '/tmp/output-01.csv'
        file_path_cap = '/tmp/output-01.cap'
        oui_file = "oui.txt"
        required_tools = ["aircrack-ng", "airgraph-ng", "tshark"]
        
        # Check oui file for manufacturer infos
        if not os.path.exists(oui_file):
            try:
                response = requests.get("https://standards-oui.ieee.org/oui/oui.txt", stream=True)
                if response.status_code == 200:
                    print(f"{Fore.GREEN}[+] {Style.RESET_ALL}Downloading oui_file datas to : {oui_file}")
                    with open(oui_file, 'wb') as file:
                        for chunk in response.iter_content(chunk_size=8192):
                            file.write(chunk)
                else:
                    print(f"\n{Fore.RED}[!] Couldn't download oui file : {Style.RESET_ALL}{response.status_code}")
            except Exception as e:
                print(f"\n{Fore.RED}[!] Couldn't download oui file : {Style.RESET_ALL}download it manually (https://standards-oui.ieee.org/oui/oui.txt) or try to disable your proxy or VPN")
                log_debug(f"{e}", include_traceback=True)
        
        check_and_install_tools(required_tools)

        try:
            print(f"{Fore.GREEN}[+] {Style.RESET_ALL}checking airodump-ng-oui-update ...")
            result = subprocess.run(
                ["sudo", "airodump-ng-oui-update"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True  # Decode output char
            )
        except subprocess.CalledProcessError as e:
            log_debug(f"Error :\n- {e}\n- {e.stdout}", include_traceback=False)
        except Exception as e:
            log_debug(f"{e}", include_traceback=True)

        # You can use airmon-ng, ifconfig, etc ...
        process = subprocess.Popen(['iwconfig'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        print(f"\n{Fore.YELLOW}[!] {Style.RESET_ALL}Available interfaces :")
        print(stdout.decode())

        # User inputs
        interface = input(f"\n{Fore.GREEN}[+] {Style.RESET_ALL}Select the interface : ").strip()
        channel = input(f"{Fore.GREEN}[+] {Style.RESET_ALL}Add commands from airodump-ng (--help to display help menu, --get to save cap files, --attack for automated attack mode) : ").strip()
        
        if channel == "--help":
            help_airodump()
            log_debug("[INFO] --help command display", include_traceback=False)
            sys.exit(0)        

        airmoncheck = input(f"{Fore.GREEN}[+] {Style.RESET_ALL}Check kill & start airmon-ng ? Will restart NetworkManager and stop monitor mode at the end : ").strip()
        setTXpower = input(f"{Fore.GREEN}[+] {Style.RESET_ALL}Up TX Power to 30 DB ? TX power will stay set to 30 DB at the end (y/n) : ").strip()
        mapping = input(f"{Fore.GREEN}[+] {Style.RESET_ALL}Setup wireless mapping at the end of the scan (airdecap-ng & airgraph-ng) (y/n) : ").strip()
        timeout_str = input(f"{Fore.GREEN}[+] {Style.RESET_ALL}Timeout after which APs & Clients are considered dead (default 60 seconds) : ")

        try:
            timeout_sec = float(timeout_str)
        except ValueError:
            print(f"{Fore.YELLOW}[!] {Style.RESET_ALL}Default value set for AP's & Clients timeout : '60'")
            log_debug("[INFO] Default value set for AP's & Clients timeout : '60'", include_traceback=False)
            timeout_sec = 60

        if mapping.lower() in ['y', 'yes']:
            mapped = "yes"
        elif mapping.lower() in ['n', 'no']:
            mapped = "no"
        else:
            print(f"{Fore.YELLOW}[!] {Style.RESET_ALL}Default value set for wireless mapping : 'no'")
            log_debug("[INFO] mapped error input. Default setting set to 'no'", include_traceback=False)
            mapped = "no"
        
        if setTXpower.lower() in ['y', 'yes']:
            TXpower = "yes"
        elif setTXpower.lower() in ['n', 'no']:
            TXpower = "no"
        else:
            print(f"{Fore.YELLOW}[!] {Style.RESET_ALL}Default value set for TXpower : 'no'")
            log_debug("[INFO] TXpower error input. Default setting set to 'no'", include_traceback=False)
            TXpower = "no"

        if TXpower == "yes":
            # Try to set at 30db
            if set_txpower(interface, 30):
                txp = get_txpower(interface)
                print(f"{Fore.GREEN}[+] {Style.RESET_ALL}TX-Power set to {txp:.2f} dBm")
            else:
                TXpower = "no"

        check_and_delete_output_file(file_path_csv, file_path_cap, script_path, save_airodump)

        if "--get" in channel:
            save_airodump = "yes"
            channel = channel.replace("--get", "").strip()  # Remove --get variable for airodump-ng command
        else:
            save_airodump = "no"

        if airmoncheck.lower() in ['y', 'yes']:
            airmon = "yes"
            try:
                out = subprocess.check_output(
                    ["sudo", "airmon-ng", "start", interface],
                    text=True, stderr=subprocess.STDOUT
                )
            except subprocess.CalledProcessError as e:
                print(f"{Fore.RED}[!] Auto use of airmon on interface failed :\n{e.output.strip()}")
                print(f"{Fore.YELLOW}[!] {Style.RESET_ALL}Try the manual way !")
                exit(1)

            # ---------- 1)  Try to read monitor mode in the output ----------
            regexes = [
                r'on\s+\[[^\]]+\](\w+mon)\b',          # mac80211 format
                r'monitor mode enabled on (\w+mon)\b', # old format
                r'\(monitor mode enabled\)',
            ]

            for rgx in regexes:
                m = re.search(rgx, out)
                if m:
                    if m.groups():
                        interface = m.group(1)
                    break

            # ---------- 2)  Fallback : maybe already on mon mode ----------
            if not m:
                try:
                    info = subprocess.check_output(["iw", "dev", interface, "info"], text=True)
                    if re.search(r'\btype\s+monitor\b', info):
                        pass
                    else:
                        raise ValueError("not monitor yet")
                except Exception:
                    # ---------- 3)  Scanner toutes les interfaces *mon -------------
                    try:
                        info = subprocess.check_output(["iw", "dev", interface, "info"], text=True)
                        mode = re.search(r'\btype\s+(\w+)', info)
                        if mode and mode.group(1) != "monitor":
                            raise ValueError(f"[!] {Fore.RED}{interface} is {mode.group(1)}, not monitor")            
                    
                    except Exception as e:
                        print(f"{Fore.RED}[!] Auto use of airmon on interface failed : \n{e}")
                        print(f"{Fore.CYAN}[!] {Style.RESET_ALL}Try the manual way !")
                        exit(1)

        elif airmoncheck.lower() in ['n', 'no']:
            airmon = "no"
        else:
            print(f"{Fore.YELLOW}[!] {Style.RESET_ALL}Default value set for Check kill airmon-ng : 'no'")
            log_debug("[INFO] airmon error input. Default setting set to 'no'", include_traceback=False)
            airmon = "no"

        if "--attack" in channel:
            channel = channel.replace("--attack", "").strip()  # Remove --attack variable for airodump-ng command
            attackmode = "yes"
            if "-f" not in channel:
                print(f"{Fore.YELLOW}[!] {Style.RESET_ALL}-f option added with value set to : '60000' (ms)")
                log_debug("[INFO] -f option added with value set to : '60000' (ms)", include_traceback=False)
        else:
            attackmode = "no"

        if "--karma" in channel:
            channel = channel.replace("--karma", "").strip()  # Remove --karma variable for airodump-ng command
            karma = "yes"

        attack_rounds = ""
        attack_time = ""

        args_dict = parse_args_to_dict(channel)

        if "--scan-rounds" in args_dict:
            attack_rounds = ["--scan-rounds", args_dict["--scan-rounds"]]
            channel = remove_args(channel, ["--scan-rounds"])

        if "--dwell-time" in args_dict:
            attack_time = ["--dwell-time", args_dict["--dwell-time"]]
            channel = remove_args(channel, ["--dwell-time"])

        airodump(script_path, channel, interface, save_airodump, airmon, attackmode)

        try:
            # Checking aviability
            result = subprocess.run(["which", "tshark"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            if result.returncode == 0:
                tsharked = "yes"
            else:
                tsharked = "no"
        except subprocess.CalledProcessError:
            tsharked = "no"
        
        time.sleep(0.5)
        check_wps_update()

        if "--karma" in channel:
            karma = "yes"

        if attackmode == "yes":
            time.sleep(3)
            
            cmd = ["python", "attacker.py", "-i", interface]

            if "--channel" in args_dict:
                cmd += ["--channel", args_dict["--channel"]]
            elif "-c" in args_dict:
                cmd += ["--channel", args_dict["-c"]]

            if "--band" in args_dict:
                cmd += ["--band", args_dict["--band"]]
            elif "-b" in args_dict:
                cmd += ["--band", args_dict["-b"]]

            if "--cswitch" in args_dict:
                cmd += ["--cswitch", args_dict["--cswitch"]]

            if attack_rounds:
                cmd += attack_rounds

            if attack_time:
                cmd += attack_time

            process_attack = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1
            )
            threading.Thread(target=stream_output, args=(process_attack,), daemon=True).start()
            print(f"{Fore.YELLOW}[!] Attack mode lanched :", " ".join(cmd))

        read_and_display_csv(file_path_csv, interface, channel, mapped, TXpower, file_path_cap, tsharked, save_airodump, timeout_sec)

    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] KeyboardInterrupt")

        if attackmode == "yes":
            print(f"{Fore.YELLOW}[!] Closing attack script")
            process_attack.kill() # Yes brutal...
        try:
            if mapped.lower() in ['y', 'yes']:
                print(f"{Fore.GREEN}[+] {Style.RESET_ALL}Launching airgraph.sh ...")
                airgraph()

        except Exception as e:
            print(f"{Fore.RED}[!] airgraph.sh couldn't be launched :")                
            print(e)
            log_debug(f"{e}", include_traceback=False)

            if airmon == "yes":
                try:    
                    print(f"{Fore.CYAN}[INFO] {Style.RESET_ALL}Stoping monitor mode")
                    result = subprocess.run(
                        ["sudo","airmon-ng","stop",interface],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True  # Decode output char
                    )
                    print(f"{Fore.CYAN}[INFO] {Style.RESET_ALL}Restarting NetworkManager")
                    result = subprocess.run(
                        ["sudo","systemctl","restart","NetworkManager.service"],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True  # Decode output char
                    )
                except Exception as e:
                    print(f"{Fore.RED}[!] Couldn't restart NetworkManager :")                
                    print(e)
                    log_debug(f"{e}", include_traceback=False)

        check_and_delete_output_file(file_path_csv, file_path_cap, script_path, save_airodump)

        if TXpower == "yes":
            print(f"{Fore.CYAN}[INFO] {Style.RESET_ALL}Command to restore TX-Power : {Fore.YELLOW}sudo iw dev <interface> set txpower fixed 2000{Style.RESET_ALL}")

        if karma == "yes":
            print(f"{Fore.YELLOW}[!] Collected ESSID from karma sniffing{Style.RESET_ALL}")
            for mot in sorted(Karma_list):
                print(f"{Fore.GREEN}[*] {Style.RESET_ALL}{mot}")

        if errors_detected:
            print(f"{Fore.RED}[ERROR] {Style.RESET_ALL}Check debug.txt")

        sys.exit(0)        
        
if __name__ == "__main__":
    main()
