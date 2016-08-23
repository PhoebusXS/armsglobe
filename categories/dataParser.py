#!usr/bin/python

import urllib2
import json
import csv
import os, fnmatch
import re
import copy

# table = {
# 	'Scans/Probes/Attempted Access'	: 'Probe',
# 	'Malicious Code'				: 'Malware',
# 	'Investigation'					: 'Investigation',
# 	'Improper Usage'				: 'Improper Usage',
# 	'Unauthorized Access'			: 'Intrusion',
# 	'Denial of Service (DoS)'		: 'DoS'
# }

enquiryCount = 0

exportLookup = {
	'Intrusion'             : 'mil',
	'Malware'               : 'civ',
	'Probe'                 : 'ammo',
};
importLookup = {
	'DoS'                   : 'mil',
	'Investigation'         : 'civ',
	'Improper Usage'        : 'ammo',
};

def halfIp(ip):
	return '.'.join(ip.split('.')[0:2])

def checkCategory(key):
	if 'Scans' in key:
		return 'Probe'
	if 'Malicious' in key:
		return 'Malware'
	if 'Investigation' in key:
		return 'Investigation'
	if 'Improper' in key:
		return 'Improper Usage'
	if 'Unauth' in key:
		return 'Intrusion'
	if 'Denial' in key:
		return 'DoS'

def find(pattern, path):
    result = []
    for root, dirs, files in os.walk(path):
        for name in files:
            if fnmatch.fnmatch(name, pattern):
                result.append(os.path.join(root, name))
    return result

def ipCountryLookup(ip):
	global enquiryCount
	if (ip[0:3] == '10.') or (ip[1] == '.'):
		print '%s ... ignored: internal' % ip
		return
	if halfIp(ip) in ipGeo:
		return ipGeo[halfIp(ip)]
	else:
		url = 'https://freegeoip.net/json/'
		gotFlag = False
		while not gotFlag:
			try:
				ipInfo = json.loads(urllib2.urlopen(url + ip).read())
				gotFlag = True
			except:
				print 'retrying...'
				pass
		if ipInfo['country_name'] != '':
			ipGeo[halfIp(ip)] = ipInfo['country_name']
			enquiryCount += 1
			print '%s ... done: %s' % (ip, ipInfo['country_name'])
			return ipInfo['country_name']
		else:
			return

def checkDataList(i, e, dataList):
	for ind, item in enumerate(dataList):
		if (item['i'] == i) & (item['e'] == e):
			return ind
	return

def logReader(file):
	dataList = []
	dataTemplate = {"i":None, "wc":None, "e":None, "v":None}
	with open(file, 'rb') as f:
		reader = csv.reader(f)
		for row in reader:
			if re.match(r'[0-9]', row[0]) != None:
				data = copy.deepcopy(dataTemplate)
				dest = row[1]
				srcIp = row[2]
				src = ipCountryLookup(srcIp)
				if src == None:
					continue
				category = row[4]
				cat = checkCategory(category)
				if cat in exportLookup:
					data['i'] = src
					data['e'] = dest
					data['wc'] = exportLookup[cat]
				if cat in importLookup:
					data['i'] = dest
					data['e'] = src
					data['wc'] = importLookup[cat]
				inList = checkDataList(data['i'], data['e'], dataList)
				if inList == None:
					data['v'] = 1
					dataList.append(data)
				else:
					dataList[inList]['v'] += 1
	return dataList

ipGeo = {}

file = find('*.csv', './')[0]

dataList = logReader(file)

dataAndTime = {"data":dataList, "t":2010}
toDump = {'timeBins':[dataAndTime]}

f = open('./app/categories/All.json', 'w')
f.write(json.dumps(toDump))

print 'total enquiry times:', enquiryCount