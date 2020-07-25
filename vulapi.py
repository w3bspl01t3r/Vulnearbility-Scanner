import requests
import json
def scan(service):
	headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0','X-VulDB-ApiKey':'edcb6e9dceea67134d633e88016eccf5'}
	url='https://vuldb.com/?api'
	data={'search':service,'details':'1'}
	response = requests.post(url,headers=headers,data=data)
	key='result'
	if response.status_code==200:
		rep=json.loads(response.content)
		if key in rep.keys():
			for i in rep['result']:
				print("\n\n")
				print("VULNERABILITY:%s" %(i['entry']['title']))
				key1='cvss3'
				try:
					print("CVSS3 SCORE IS:%s" %(i['vulnerability']['cvss3']['meta']['basescore']))
				except:
					print("CVSS3 NOT FOUND")
					print("CVSS2 SCORE IS:%s"%(i['vulnerability']['cvss2']['vuldb']['basescore']))
				key2='cve'
				try:
					print("CVE IS:%s" % (i['source']['cve']['id']))
				except:
					print("CVE NOT FOUND")
		else:
			print("NO VULNERABILITY FOUND")
