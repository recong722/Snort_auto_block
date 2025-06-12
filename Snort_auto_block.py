import subprocess
import os
import time
ALERT_LOG_FILE = "/var/log/snort/snort.alert.fast"
LOG_FILE = '/var/log/snort/Failed_Login.txt'
blocked_ip=[]

def block_ip(ip_address):
#subprocess를 통해 셀 명령어를 실행한다.중복되지않도록 blocked_ip에 ip_address가 있는지 확인하고 없다면 추가한 후에 차단 규칙을 생성한다.
    if ip_address in blocked_ip:
        return
    blocked_ip.append(ip_address)
    subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'LOG','--log-prefix','iptables 공격 차단'])
    subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'])

    
      
def parse_alert_log(file_path):
#이 코드를 실행한 이후에 추가되는 공격 시도 로그를 읽어 ip부분을 분리한 후 block_ip함수로 실행하여 차단을 수행한다.
    initial_position = os.path.getsize(file_path)
    while True:
        if not os.path.exists(file_path):
            time.sleep(5)
            continue
        current_position = os.path.getsize(file_path)
        with open(file_path, 'r') as file:
            # Adjust starting point based on initial file size
            start_position = initial_position if current_position - initial_position != 0 else 0
            if start_position == 0:
                continue
            else:
                file.seek(start_position)
                for line in file.readlines():
                    if "SYN_Flooding" in line:
                        parts = line.strip().split(' [**] ')
                        if len(parts) >= 3:
                            timestamp = parts[0]
                            IPs = parts[2].split('{TCP}')[1]
                            srcIP = IPs.split(' -> ')[0]
                            source_ip = srcIP.split(':')[0]
                            block_ip(source_ip)
                    if "Port_Scan" in line:
                        parts = line.strip().split(' [**] ')
                        if len(parts) >= 3:
                            timestamp = parts[0]
                            IPs = parts[2].split('{TCP}')[1]
                            srcIP = IPs.split(' -> ')[0]
                            source_ip = srcIP.split(':')[0]
                            block_ip(source_ip)
                        
                            
