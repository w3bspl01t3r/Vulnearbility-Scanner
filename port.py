import nmap
import vulapi
nm=nmap.PortScanner()
nm.scan('192.168.1.102','21-23')
services=[]
apikeys=[]
for host in nm.all_hosts():
	print("Scanning for :%s (%s)" % (host,nm[host].hostname()))
	for proto in nm[host].all_protocols():
		print('-'*60)
		lport=nm[host][proto].keys()
		lport.sort()
		print("*"*20+"OPEN PORTS ARE"+"*"*20)
		for port in lport:
			product=nm[host][proto][port]['product']
			version=nm[host][proto][port]['version']
			service=product+" "+version
			services.append(service)
			print("Port:%s \tstate: %s\tService: %s" % (port,nm[host][proto][port]['state'],service))
print("*"*20+"DETECTING VULNERABILITIES"+"*"*20)
print("\n\n")
for i in services:
	print("\n\n")
	print("VULNERABILITIES FOR:%s"%i)
	print("*"*60)
	vulapi.scan(i)


