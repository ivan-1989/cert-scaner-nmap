#!/usr/bin/env python3

from nmap3 import NmapScanTechniques
import nmap3
import OpenSSL
import ssl
import sys



h = NmapScanTechniques()
tcp_syn_scan = h.nmap_syn_scan(sys.argv[1])

print('\n')
print('{0:29}|{1:45}|{2}'.format('host',' cert serial Number', ' cert CN'))
print('-----------------------------|---------------------------------------------|--------------')


for host in tcp_syn_scan.keys():
     for port in tcp_syn_scan[host]:
        try:
            if "host" in port:
                if port['portid'] == '443':
                    cert_pem = ssl.get_server_certificate((port['host'], 443))
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
                    subject = x509.get_subject()
                    print('{0:30}{1:46}{2}'.format(port['host'],hex(x509.get_serial_number()),subject.CN))
        except:
            break
