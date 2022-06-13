#!/usr/bin/python3

from urllib import request
from scapy.all import *
from random import randint
import argparse, time, socket, signal, re, requests



def clear():
    os.system('cls')

def def_handler(sig, frame):
    print ("\n [!] Exiting...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def arp_ping(target):
    clear()
    banner()
    print("( A | R | P ) ( P | i | n | g )")
    ipSplit = target.split('.')
    red = ipSplit[0]+'.'+ipSplit[1]+'.'+ipSplit[2]+'.'
    ip=red+"0/24"
    print ("Target: "+ ip)
    print( "Scaning... ")
    print("")
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),timeout=2, verbose=False)
    ans.summary(lambda s,r: r.sprintf("%ARP.psrc% is UP"))
    print("")

def syn_ping(target):
    clear()
    banner()
    print("( S | Y | N ) ( P | i | n | g )")
    print ("Target: "+ target)
    print( "Scaning... ")
    print("")
    i=1
    port_range=[8,21,22,23,25,42,43,49,53,80,85,88,111,139,443,445,3306,3389,4443,8080]
    list=[]
    ipSplit = target.split('.')
    red = ipSplit[0]+'.'+ipSplit[1]+'.'+ipSplit[2]+'.'
    for host in range(1,2):
        clear()
        banner()
        print("Target: "+red+str(host))
        for port in port_range:
            target=red+str(host)
            tcpRequest = IP(dst=target)/TCP(dport=port,flags="S")
            tcpResponse = sr1(tcpRequest,timeout=0.3,verbose=False)
            try:
                if tcpResponse.getlayer(TCP).flags == "SA":
                    list.append(target)
                    break 
            except AttributeError:
                pass
    clear()
    banner()
    print("( S | Y | N ) ( P | i | n | g )")
    print("")
    if list != 0:
        for tar in list:
            print(tar+ " is UP")
	       	 
def icmp_ping(target):
    clear()
    banner()
    print("( I | C | M |P ) ( P | i | n | g )")
    print( "Scaning... ")
    print("")
    list=[]
    ipSplit = target.split('.')
    red = ipSplit[0]+'.'+ipSplit[1]+'.'+ipSplit[2]+'.'
    for ip in range (1, 256):
        clear()
        banner()
        print("( I | C | M |P ) ( P | i | n | g )")
        print( "Scaning... ")
        print ("Target: "+ red+str(ip))
        print("")
        try:
            packet = IP(dst=(red + str(ip)), ttl=20)/ICMP()
            reply = sr1(packet, timeout=0.5, verbose=False)
            if not (reply is None):
                host=red+str(ip)
                list.append(host)
            else: 
                pass
        except:
            pass
    clear()
    banner()
    print("( I | C | M |P ) ( P | i | n | g )")
    print("")
    if list != 0:
        for tar in list:
            print(tar+ " is UP")
    print("")
            
def udp_ping(target):
    clear()
    banner()
    print("( U | D | P ) ( P | i | n | g )")
    print ("Target: "+ target)
    print( "Scaning... ")
    print("")
    ip = target
    port_range=[7,9,11,13,17,18,19,37,42,49,53,67,68,69,71,73,74,80,88,104,105,107,108,111]
    list=[]
    ipSplit = target.split('.')
    red = ipSplit[0]+'.'+ipSplit[1]+'.'+ipSplit[2]+'.'
    status=0
    for host in range (1, 256):
        clear()
        banner()
        print("( U | D | P ) ( P | i | n | g )")
        print("")
        print ("Scanning: "+ red+str(host))
        print("")
        ip=red+str(host) 
        for port in port_range:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.connect((ip, int(port)))
                list.append(ip)
                s.close
                break
            except:
                pass
                s.close()
    clear()
    banner()
    print("( U | D | P ) ( P | i | n | g )")
    print("")
    if list != 0:
        for tar in list:
            print(tar+ " is UP")
    print("")

def syn_scan(target):
    i=1
    status_host=0
    clear()
    banner()
    print("( S | Y | N ) ( S | c | a | n )")
    print ("Target: "+ target)
    print( "Scaning... ")
    print("")
    while i <= 1024:
	    tcpRequest = IP(dst=target)/TCP(dport=i,flags="S")
	    tcpResponse = sr1(tcpRequest,timeout=0.5,verbose=0)
	    try:
	       	if tcpResponse.getlayer(TCP).flags == "SA":
                    src_port = random.randint(1025,65534)
                    status_host=1 
                    resp = sr1(IP(dst=target)/TCP(sport=src_port,dport=i,flags="S"),timeout=1, verbose=0)
                    time.sleep(0.5)
                    if resp is None:
                        print(f"{target} : {i} is filtered.")
                    elif(resp.haslayer(TCP)):
                        if(resp.getlayer(TCP).flags == 0x12):
                            send_rst = sr( IP(dst=target)/TCP(sport=src_port,dport=i,flags='R'), timeout=1, verbose=0)
                            grab_banner(target,i)
                        elif (resp.getlayer(TCP).flags == 0x14):
                            pass
	    except AttributeError:
	       	if i == 1024 and status_host==0: 
	            print(target," is Down")
	    i+=1
        	       	     
def udp_scan(target):
    clear()
    banner()
    print("( U | D | P ) ( S | c | a | n )")
    print ("Target: "+ target)
    print( "Scaning... ")
    print("")
    ip = target
    for port in range(1,600):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((ip, int(port)))
            print(target + " "+ str(port) + "/TCP is Open") 
        except:
            pass
        s.close()
    print("")

def tcp_scan(target):
    clear()
    banner()
    print("( T | C | P ) ( S | c | a | n )")
    print ("Target: "+ target)
    print( "Scaning... ")
    print("")
    host = target
    for dst_port in range(1,1024):
        src_port = random.randint(1025,65534)
        resp = sr1(IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=1, verbose=0)
        time.sleep(0.5)
        if resp is None:
            print(f"{host} : {dst_port} is filtered.")
        elif(resp.haslayer(TCP)):
            if(resp.getlayer(TCP).flags == 0x12):
                send_rst = sr( IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags='R'), timeout=1, verbose=0)
                grab_banner(host,dst_port)
            elif (resp.getlayer(TCP).flags == 0x14):
                pass
        elif(resp.haslayer(ICMP)):
            if(
                int(resp.getlayer(ICMP).type) == 3 and
                int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]
            ):
                print(f"{host}:{dst_port} is filtered (silently dropped).")

def ack_test(target):
    clear()
    banner()
    print("( F | I | R | E | W | A | L | L ) ( D | E | T | E | C | T | I | O | N )")
    print("")
    print ("Target: "+ target)
    print("")
    ip = target
    src_port = RandShort()
    status=0

    port_range=[7,9,13,17,19,26,30,32,33,37,42,43,49,53,70,79,85,88,90,99,100,106,109,111,139,143,144,146,161,163,179,199,211,212,222,254,366,389,443,445,458,464,465,481,497,500,512,515,787,800,801,808,843,873,880,888,898,900,903,911,912,981,987,990,992,993,995,999,1002,1169,3306,3322,3325,3333,3351,3367,3369,3372,3389,3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689,3690,3703,3737,3766,3784,3800,3801,3809,3814,4443,4446,4449,4550,4567,4662,4848,4899,4900,6543,6547,6565,6567,6580,6646,6666,6669,6689,6692,6699,6779,6788,6789,6792,6839,6881,6901,6969,7100,7103,7106,7200,7443,7496,8042,8045,8080,8090,8093,8099,8100,8180,8181,8192,8194,8200,8800,8873,8888,8899,8994,9000,9003,9009,9011,9040,9050,9071,9080,9081,9090,44443,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055,55056,55555,55600]
    for dst_port in port_range: 
        clear()
        banner()
        print("( F | I | R | E | W | A | L | L ) ( D | E | T | E | C | T | I | O | N )")
        print("")
        print ("Target: "+ target + " / Port: " + str(dst_port))
        print("")
        ack_pkt = sr1(IP(dst=ip)/TCP(dport=dst_port,flags="A"),timeout=0.5, verbose=False)
        try:
            if (ack_pkt==None):
                status=1
            elif(ack_pkt and ack_pkt.haslayer(TCP) and ack_pkt.getlayer(TCP).flags=='R'): 
                if(ack_pkt.getlayer(TCP).flags == 0x4):
                    status=2
                    break
                elif(ack_pkt.haslayer(ICMP)):
                    if(int(ack_pkt.getlayer(ICMP).type)==3 and int(ack_pkt.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                        status=3
        except:
            print("Host unreacheble.")
            print("         _______")
            print("        |.-----.|")
            print("        ||x . x||")
            print("        ||_.-._||")
            print("        `--)-(--`")
            print("        __[=== o]___")
            print("        |:::::::::::|")
            print("         `-=========-`()")
            print("")
            print("")

    if status==1:
        print("Stateful firewall present (Filtered) or host unreachable")
        print("         _______")
        print("        |.-----.|")
        print("        ||x . x||")
        print("        ||_.-._||")
        print("        `--)-(--`")
        print("        __[=== o]___")
        print("        |:::::::::::|")
        print("         `-=========-`()")
        print("")
    elif (status == 2):
            print("   ---  No firewall has been detected ---")
            print("                  .----.")
            print("      .---------. | == |")
            print("      |.-------.| |----|")
            print("      ||  *  * || | == |")
            print("      ||  \__/ || |----|")
            print("      |'-.....-'| |::::|")
            print("      `--)---(--` |___.|")
            print("     /::::::::::: _  ")
            print("    /:::=======:::\`\`")
            print("     `------------  '-'")
            print("")
    elif (status==3):
            print("Stateful firewall present (Filtered) or host unreachable")
            print("         _______")
            print("        |.-----.|")
            print("        ||x . x||")
            print("        ||_.-._||")
            print("        `--)-(--`")
            print("        __[=== o]___")
            print("        |:::::::::::|")
            print("         `-=========-`()")
            print("")

def grab_banner(target,port): 
    try:
        s=socket.socket()  
        s.connect((target,port))
        s.send(b'GET /\n\n')
        resp=str(s.recv(1024))
        if re.search("HTTP", resp):
            res=requests.get("http://"+target+":"+str(port))
            print(target +" : "+ str(port) +" / "+ res.headers['server'])
 
        else: 
            print (target + " : " + str(port) + " / " + str(resp).strip('b')) 
 
    except:  
        return 

def OS_identifier(target):
    clear()
    banner()
    packet = IP(dst=target, ttl=20)/ICMP()
    reply = sr1(packet, timeout=0.5, verbose=False)
    ttl = reply.ttl
    if ttl >= 0 and ttl <= 64:
            print ("OS: Linux")
    elif ttl >= 65 and ttl <= 128:
        print ("OS: Windows")
    else:
        print ("OS Not identified")

def banner():
    print("")
    print(" ____ ____ ____ ____ ____ ____ _________ ____ ____ ____      ──▄────▄▄▄▄▄▄▄────▄───")
    print("||P |||Y |||S |||C |||A |||N |||       |||T |||F |||M ||     ─▀▀▄─▄█████████▄─▄▀▀──")
    print("||__|||__|||__|||__|||__|||__|||_______|||__|||__|||__||     ─────██─▀███▀─██──────")
    print("|/__\|/__\|/__\|/__\|/__\|/__\|/_______\|/__\|/__\|/__\|     ───▄─▀████▀████▀─▄────")
    print("                                                             ─▀█────██▀█▀██────█▀──")
    print("")

def targ():
    target=input("Target: ")
    return target

def menu():
    print("")
    print("[1] Check for firewalls")
    print("[2] ARP Ping")
    print("[3] Syn Ping")
    print("[4] ICMP Ping")
    print("[5] UDP Ping")
    print("[6] Syn Scan")
    print("[7] TCP Scan")
    print("[8] UDP Scan")
    print("")
    option = input("Choose an option:")
    print("")
    
    if option == "1":
        target=targ()
        ack_test(target) 
    elif option== "2":
        target=targ()
        arp_ping(target)
    elif option== "3":
        target=targ()
        syn_ping(target)
    elif option== "4":
        target=targ()
        icmp_ping(target)
    elif option== "5":
        target=targ()
        udp_ping(target)
    elif option== "6":
        target=targ()
        syn_scan(target)
    elif option== "7":
        target=targ()
        tcp_scan(target)
    elif option=="8":
        target=targ()
        udp_scan(target)
    else:
        print(" -- Invalid Option -- ")


if __name__ == "__main__": 
    clear()
    banner()
    print("------------------------------------------")
    menu()
    

        
	
