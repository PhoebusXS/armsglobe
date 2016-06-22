#!usr/bin/python

import urllib2
import json

def ipCountryLookup(ip):
	url = 'http://ip-api.com/json/'
	ipInfo = json.loads(urllib2.urlopen(url + ip).read())
	return ipInfo['country']

print ipCountryLookup('25.100.134.238') #test

