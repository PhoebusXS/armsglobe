#!usr/bin/python

import urllib2
import json

def ipCountryLookup(ip):
	url = 'http://ip-api.com/json/'
	ipInfo = json.loads(urllib2.urlopen(url + ip).read())
	return ipInfo['country']

def logReader():
	dataTemplate = {"i":None, "wc":None, "e":None, "v":None}
	line = dataTemplate
	return line

def lineCounter():
	return num

# test
print ipCountryLookup('25.100.134.238')

dataList = []
for i in range(lineCounter(file)):
	line = logReader()
	dataList.append(line)

dataAndTime = {"data":dataList, "t":2010}
toDump = {'timeBins':dataAndTime}

f = open('All.json', w)
f.write(json.dump(toDump))
