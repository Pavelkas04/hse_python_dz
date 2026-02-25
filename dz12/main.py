import pyshark
import pandas as pd
import matplotlib.pyplot as plt

pcap_file = 'dz12/dhcp.pcapng'
cap = pyshark.FileCapture(pcap_file)

dhcp_requests = []
for packet in cap:
    try:
        if 'DHCP' in packet:
            dhcp_requests.append({
                'time': packet.sniff_time,
                'dhcp_type': packet.dhcp.option_dhcp,
                'src_ip': packet.ip.src,
                'dst_ip': packet.ip.dst,
                'client_mac': packet.dhcp.hw_mac_addr,
                'offered_ip': packet.dhcp.ip_your,
            })
    except AttributeError:
        continue

df_dhcp = pd.DataFrame(dhcp_requests)
print(df_dhcp)
type_counts = df_dhcp['dhcp_type'].value_counts()
print(type_counts)

df_dhcp['time'] = pd.to_datetime(df_dhcp['time'])
df_dhcp['second'] = df_dhcp['time'].dt.floor('s')
dhcp_by_time = df_dhcp.groupby('second').size()
plt.figure()
dhcp_by_time.plot(kind='bar')
plt.xlabel('Время')
plt.ylabel('Количество DHCP-запросов')
plt.title('DHCP-запросы по времени')
plt.savefig('dz12/output/dhcp_by_time.png')
plt.show()

with open('dz12/output/dhcp_events.txt', 'w', encoding='utf-8') as f:
    f.write(df_dhcp.to_string(index=False))
