import csv, time, os, sys, subprocess, requests, traceback, gc
from datetime import datetime
from itertools import cycle
from subprocess import Popen, PIPE
from colorama import init, Fore, Style
init() # Init colorama



#################################################################
#######################   Errors & debug  #######################
#################################################################

DEBUG_FILE_PATH = "debug.txt" # If there are some errors, it will appears here

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

def airodump(script_path, channel, interface, save_airodump, airmon):
    save_airodump2 = ""
    
    if save_airodump == "yes":
        save_airodump2 = ""
    else:
        save_airodump2 = " --output-format csv,cap"
        
    bash_script = ""
    
    # Step 1 : create bash file
    bash_script = f"""#!/bin/bash
    airodump-ng {interface} --write /tmp/output{save_airodump2} --write-interval 3 --background 1 {channel}
    """
    
    if airmon == "yes": # add airmon-ng check kill to script
        bash_script = f"""#!/bin/bash
        airmon-ng check kill
        airodump-ng {interface} --write /tmp/output{save_airodump2} --write-interval 3 --background 1 {channel}
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
      --get  : Get all airodump-ng outputs without deleting them by closing the script (located in /tmp directory)
  
  {Fore.GREEN}------------------------------------------------------------------------{Style.RESET_ALL}
  Internal functionnement:
      airodump-ng <selected interface> --write /tmp/output --output-format csv,cap --write-interval 3 --background 1 <your commands inputs>
      manufacturer comes from oui file
      wps infos comes from the extract .cap file made by airodump-ng
      Last seen AP and Clients before timeout : 120s (4min)

  Aigraph functionnement (wireless mapping):
      airgraph-ng -o CAPR_png -i /tmp/output-01.csv -g CAPR
      airgraph-ng -o CPG_png -i /tmp/output-01.csv -g CPG
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
        ]
        
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

bssid_color_map = {} # Store the list of colors assigned to the BSSIDs
used_colors = [] # Store a list of colors that have already been assigned
tsharked = "" # Check tshark installation for WPS checkin
cycle_counter = 0 # Refresh wps every 3 read_and_display_csv cycle
mapped = "no"
airmon = "no"

def read_and_display_csv(file_path, interface, channel, mapped, file_path_cap, tsharked, save_airodump):
    """Display CSV data from airodump-ng with unique colors for each matched BSSID."""
    global cycle_counter
    
    try:
        tsharkinfos = " |"
        mappedinfos = "Network mapping disabled"
        
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
        
        try:
            with open(file_path, mode='r', newline='', encoding='utf-8') as csvfile:
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
                client_bssids = {row[5].strip() for row in station_data if len(row) > 0 and row[5].strip()}


                # Clear unused used_colors and bssid_color_map
                for bssid, color in list(bssid_color_map.items()):
                    if bssid not in ap_bssids and bssid not in client_bssids:
                        used_colors.remove(color)  
                        del bssid_color_map[bssid]  # Clear inactives BSSID colors attribued


                # Create a color palette for the matches
                color_palette = get_color_palette()

                # Assign a unique color to the BSSIDs that appear in both the APs and the clients
                for bssid in ap_bssids & client_bssids:
                    if bssid not in bssid_color_map:  # Assign a color if it has not been assigned
                        try:
                            color = next(color_palette)
                        except StopIteration:  # Restart iteration if all colors where used
                            color_palette = get_color_palette()
                            color = next(color_palette)

                        bssid_color_map[bssid] = color
                        used_colors.append(color)  # Set used colors

                # Show data after clearing the console
                clear_console()

                # AP's
                print(f"{Fore.YELLOW}[!] Listening on {interface} on {bandz}{tsharkinfos} {mappedinfos}\n")
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
                            if time_difference.total_seconds() > 240:  # timeout 4min --> realtime live clients
                                continue
                            else:
                            
                                power_color = get_signal_color(row[8])  # Color based on the signal strength
                                bssid = row[0].strip()
                                
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
                                    
                                print(f"{bssid_color}{bssid:<20}{row[3]:<10}{row[9]:<15}{security_color}{row[5]:<15}{bssid_color}{row[6]:<15}{MGT_color}{row[7]:<17}{power_color}{row[8]:<10}{Style.RESET_ALL}{wps_color}{format_text(wps_status, 20)}{Style.RESET_ALL}{bssid_color}{format_text(row[13], 20)}{manufacturer}{Style.RESET_ALL}")
                        except Exception as e:
                            log_debug(f"{e}", include_traceback=True)
                            continue

                # Clients
                print(f"\n{Fore.CYAN}==== Clients (Stations) ===={Style.RESET_ALL}")
                print(f"{'Station MAC':<20}{'Manufacturer':<30}{'Power':<10}{'# Packets':<15}{'BSSID':<20}{'Probed ESSIDs'}")
                print('-' * 109)
                for row in station_data:
                    if len(row) > 1 and row[2].strip() != "Last time seen":
                        try:
                            format_str = "%Y-%m-%d %H:%M:%S"  # format
                            date_obj = datetime.strptime(row[2].strip(), format_str)
                            current_time = datetime.now()
                            time_difference = current_time - date_obj
                            if time_difference.total_seconds() > 240:  # timeout 4min --> realtime live clients
                                continue
                            else:
                            
                                station_mac = row[0].strip()
                                manufacturer = get_manufacturer(station_mac, manufacturer_map)
                                
                                power_color = get_signal_color(row[3])  # Color based on the signal strength
                                
                                bssid = row[5].strip()  # Client associated BSSID
                                bssid_color = bssid_color_map.get(bssid, "")  # Get unique color if matched
                                
                                print(f"{bssid_color}{row[0]:<20}{format_text(manufacturer, 30)}{power_color}{row[3]:<10}{Style.RESET_ALL}{bssid_color}{row[4]:<15}{bssid:<20}{row[6]}{Style.RESET_ALL}")
                        except Exception as e:
                            log_debug(f"{e}", include_traceback=True)
                            continue

                

                if cycle_counter >= 3:
                    cycle_counter = 0  # Reset cycle to 0
                    
                    if tsharked == "no":
                        pass
                    else:                     
                        check_wps_update()
                        
                # Free memory to avoid crash
                ap_data.clear()
                station_data.clear()
                del ap_data, station_data
            
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
        print(save_airodump)
        if mapped.lower() in ['y', 'yes']:
            try:
                print(f"{Fore.GREEN}[+] {Style.RESET_ALL}Launching airgraph.sh ...")
                airgraph()
            except Exception as e:
                print(f"{Fore.RED}[!] airgraph.sh couldn't be launched :")                
                print(e)
                log_debug(f"{e}", include_traceback=False)

            try:
                if airmon == "yes":
                    print(f"{Fore.CYAN}[INFO] {Style.RESET_ALL}Restarting NetworkManager")
                    result = subprocess.run(
                        ["sudo", "NetworkManager", "restart"],
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
        sys.exit(0)          
    except Exception as e:
        pass


#################################################################
#########################   Launching   #########################
#################################################################

def main():
    global cycle_counter
    
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
        channel = input(f"{Fore.GREEN}[+] {Style.RESET_ALL}Add commands from airodump-ng (--help to display aviable commands aviable with this tool) : ").strip()
        
        if channel == "--help":
            help_airodump()
            log_debug("[INFO] --help command display", include_traceback=False)
            sys.exit(0)        

        airmoncheck = input(f"{Fore.GREEN}[+] {Style.RESET_ALL}Check kill (airmon-ng) ? NetworkManager will restart at the end (y/n) : ").strip()
        mapping = input(f"{Fore.GREEN}[+] {Style.RESET_ALL}Setup wireless mapping at the end of the scan (airdecap-ng & airgraph-ng) (y/n) : ").strip()
        
        if mapping.lower() in ['y', 'yes']:
            mapped = "yes"
        elif mapping.lower() in ['n', 'no']:
            mapped = "no"
        else:
            print(f"{Fore.YELLOW}[!] {Style.RESET_ALL}Default value set : 'no'")
            log_debug("[INFO] mapped error input. Default setting set to 'no'", include_traceback=False)
            mapped = "no"
        
        
        check_and_delete_output_file(file_path_csv, file_path_cap, script_path, save_airodump)


        if "--get" in channel:
            save_airodump = "yes"
            channel = channel.replace("--get", "").strip()  # Remove --get variable for airodump-ng command
        else:
            save_airodump = "no"

        if airmoncheck.lower() in ['y', 'yes']:
            airmon = "yes"
        elif airmoncheck.lower() in ['n', 'no']:
            airmon = "no"
        else:
            print(f"{Fore.YELLOW}[!] {Style.RESET_ALL}Default value set : 'no'")
            log_debug("[INFO] airmon error input. Default setting set to 'no'", include_traceback=False)
            airmon = "no"


        airodump(script_path, channel, interface, save_airodump, airmon)


        try:
            # Checking aviability
            result = subprocess.run(["which", "tshark"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            if result.returncode == 0:
                tsharked = "yes"
            else:
                tsharked = "no"
        except subprocess.CalledProcessError:
            tsharked = "no"
        
        time.sleep(3)
        check_wps_update()
        
        while True:
            cycle_counter += 1
            time.sleep(5)  # Refresh every 2s
            try:
                read_and_display_csv(file_path_csv, interface, channel, mapped, file_path_cap, tsharked, save_airodump)
                
            except KeyboardInterrupt:
                print(f"\n{Fore.RED}[!] KeyboardInterrupt")
                try:
                    if mapped.lower() in ['y', 'yes']:
                        print(f"{Fore.GREEN}[+] {Style.RESET_ALL}Launching airgraph.sh ...")
                        airgraph()
                except Exception as e:
                    print(f"{Fore.RED}[!] airgraph.sh couldn't be launched :")                
                    print(e)
                    log_debug(f"{e}", include_traceback=False)

                try:
                    if airmon == "yes":
                        print(f"{Fore.CYAN}[INFO] {Style.RESET_ALL}Restarting NetworkManager")
                        result = subprocess.run(
                            ["sudo", "NetworkManager", "restart"],
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
                sys.exit(0)         
            
            finally:
                gc.collect() # Free memory to avoid crash


    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] KeyboardInterrupt")
        try:
            if mapped.lower() in ['y', 'yes']:
                print(f"{Fore.GREEN}[+] {Style.RESET_ALL}Launching airgraph.sh ...")
                airgraph()

        except Exception as e:
            print(f"{Fore.RED}[!] airgraph.sh couldn't be launched :")                
            print(e)
            log_debug(f"{e}", include_traceback=False)

        try:
            if airmon == "yes":
                print(f"{Fore.CYAN}[INFO] {Style.RESET_ALL}Restarting NetworkManager")
                result = subprocess.run(
                    ["sudo", "NetworkManager", "restart"],
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
        sys.exit(0)        
        
if __name__ == "__main__":
    main()
