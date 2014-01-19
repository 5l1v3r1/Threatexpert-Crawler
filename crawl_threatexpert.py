#!/usr/bin/python
from BeautifulSoup import BeautifulSoup
import urllib
import simplejson
import re, sys, os
import psycopg2 as pg
import psycopg2.extras

BTICOIN_CONNECTIONS="bitcoin_connections"
LOGINS="logins"
EXECUTIONS="executions"
MISC_CONN="misc_connections"
HTTP_CON="http_conn"
URLS_REQUESTED="urls_requested"
OUTBOUND="outbound_comm"

HTTP_READ="HTTP_READ"
HTTP_REQUEST="HTTP_REQUEST"
GET="GET"

base='https://www.googleapis.com/customsearch/v1?'
cx=''
key=''
num=100
drange="d30"


USAGE="""
Usage: testing_threatexpert.py [options] [url]
options: 
		crawl = Start Crawling
		db = re-run from table api_results_cache
		url = scrape the url specified in [url]

"""
try:
	con = pg.connect(database='threatexpert', user='hitesh', host='localhost', password='password')    
	cur = con.cursor(cursor_factory=psycopg2.extras.DictCursor)

except pg.DatabaseError, e:
    print 'Error %s' % e    
    sys.exit(1)

def check_pool(hostname_of_pool):
	build_q="select * from all_pools where host ilike '%"+str(hostname_of_pool)+"'"
	cur.execute(build_q)
	if cur.fetchall():
		return 1
	else:
		return 0

def add_to_db(which_table,the_list):
	build_q=None
	if which_table==EXECUTIONS:
		build_q="insert into executions(md5,te_url,ts) values('%s','%s',NOW()) returning id" % (the_list['md5'],the_list['te_url'])
		cur.execute(build_q)
		return cur.fetchone()[0]
	if which_table==BTICOIN_CONNECTIONS:
		build_q="insert into bitcoin_connections values(%s,'%s',%s)" % (the_list['exec_id'],the_list['host'],the_list['port'])
	if which_table==LOGINS:
		build_q="insert into logins values(%s,'%s','%s','%s',%s,%s) " % (the_list['exec_id'],the_list['username'],the_list['password'],the_list['hostname'],the_list['port'],check_pool(the_list['hostname']))
	if which_table==MISC_CONN:
		build_q="insert into misc_connections values(%s,'%s',%s)" % (the_list['exec_id'],the_list['host'],the_list['port'])
	if which_table==OUTBOUND:
		build_q="insert into outbound_comm values(%s,'%s')" % (the_list['exec_id'],the_list['pcap'])
	if which_table==URLS_REQUESTED:
		build_q="insert into urls_requested values(%s,'%s','%s')" % (the_list['exec_id'],the_list['url'],the_list['type'])
	
	print build_q
	try:
		cur.execute(build_q)	
	except:
		pass
	con.commit()

def cache_google_results(addthis):
	build_q="insert into api_results_cache values('%s,NOW()')" % addthis
	cur.execute(build_q)
	con.commit()

def check_if_scraped(url):
	build_q="select * from executions where te_url='%s' " % url
	cur.execute(build_q)
	if cur.fetchall():
		return 1
	else:
		return 0

def get_from_api_cache():
	url_list=[]
	cur.execute("select distinct url from api_results_cache")
	tmp=cur.fetchall()
	for every in tmp:
		url_list.append(every[0])
	return url_list


def main():

	if len(sys.argv)<2:
		print USAGE
		sys.exit(1)
	if len(sys.argv)==2 and sys.argv[1]=="url":
		print USAGE
		sys.exit(1)

	urls = []

	if sys.argv[1]=="db":
		urls=get_from_api_cache()
	elif sys.argv[1]=="url":
		urls.append(sys.argv[2])
	elif sys.argv[1]=="crawl":
		params = {'cx' : cx, 'key': key, "q": "bitminer", "as_qdr":drange}
		query = urllib.urlencode(params)
		url = base + query

		print >> sys.stderr, url
		search_results = urllib.urlopen(url)
		searchcontent = search_results.read()
		json = simplejson.loads(searchcontent)
		print json


		try:
		    total = json['queries']['request'][0]['totalResults']
		    if total > 100:
		        total = 100

		    recv = 0
		except:
		    print searchcontent
		    sys.exit(0)

		try:
		    while recv <= total: 
		        recv += json['queries']['request'][0]['count']
		        for i in json['items']:
		            urls.append(i['link'])
		            print >> sys.stderr, i['link']
		            cache_google_results(i['link'])

		        params['start'] = recv+1
		        query = urllib.urlencode(params)
		        url = base + query
		        search_results = urllib.urlopen(url)
		        json = simplejson.loads(search_results.read())
		except Exception, e:
		    print >> sys.stderr, "Got %d/%d but exception occurred" % (recv,total)
		    print >> sys.stderr, e 
		

	for u in urls:	
		if check_if_scraped(u):
			print u+" is already scraped. Skipping"
			continue
		if 'http://www.threatexpert.com/report.aspx?md5' not in u:
			print u+" does not look like a malware report. Skipping"
		print u
		te_page = urllib.urlopen(u)
		almd5=u.split('=')[1]
		the_list={}
		the_list['md5']=almd5
		the_list['te_url']=u
		run_id=add_to_db(EXECUTIONS,the_list)
		tecontents = te_page.read()
		soup=BeautifulSoup(tecontents)
		alltables=soup.findAll('table')
		all_uls=soup.findAll('ul')
		all_text=soup.findAll('textarea')
		for one in alltables:
			if one.td.text=='Remote Host':
				allhosts=one.td.findAllNext('td',{'class':'cell_1'})
				allports=one.td.findAllNext('td',{'class':'cell_2'})
				if len(allhosts)==len(allports):
					i=0
					for host in allhosts:
						the_list['exec_id']=run_id
						the_list['host']=host.text
						the_list['port']=allports[i].text
						if allports[i].text=="8332" or allports[i].text=="8333":
							add_to_db(BTICOIN_CONNECTIONS,the_list)
							print host.text+"   "+allports[i].text
						else:
							add_to_db(MISC_CONN,the_list)
							print host.text+"   "+allports[i].text
						i+=1
			if one.td.text.find('Connection Password')!=-1 or one.td.text.find('Connect as User')!=-1:
				servername=one.td.findAllNext('td',{'class':'cell_1'})[0].text
				onport=one.td.findAllNext('td',{'class':'cell_1'})[1].text
				username=one.td.findAllNext('td',{'class':'cell_1'})[2].text
				password=one.td.findAllNext('td',{'class':'cell_2'})[0].text
				the_list['exec_id']=run_id
				the_list['username']=username
				the_list['password']=password
				the_list['hostname']=servername
				the_list['port']=onport
				if username!=password:
					add_to_db(LOGINS,the_list)
					print md5+" uses Username: "+username+"and Password: "+password
			if 'Outbound traffic' in one.text:
				#print "Outbound traffic"
				communications=soup.findAll('textarea')
				for each in communications:
					parts=each.text.split('|')
					if parts[0]==each.text:
						the_list['pcap']=parts[0]
						the_list['exec_id']=run_id
						add_to_db(OUTBOUND,the_list)
					else:
						try:
							z=""
							for i in range(len(parts)):
								if i%2==1:
									z=str(z)+str(parts[i])
							z=z.replace('None','')
							z=z.replace(' ','')
							#print z
							the_list['pcap']=z.decode("hex")
							the_list['exec_id']=run_id
							add_to_db(OUTBOUND,the_list)
						except:
							continue


		for one in all_uls:
			if 'following URL was then requested' in one.li.text:
				for i in one.contents[2].text.split('http'):
					if str(i)!='':
						the_list['exec_id']=run_id
						the_list['url']="http"+i
						the_list['type']=HTTP_REQUEST
						add_to_db(URLS_REQUESTED,the_list)
			if 'GET request was made' in one.li.text:
				the_list['exec_id']=run_id
				the_list['url']=one.contents[2].text
				the_list['type']=GET
				add_to_db(URLS_REQUESTED,the_list)
			if 'HTTP URL was started reading' in one.li.text:
				the_list['exec_id']=run_id
				the_list['url']=one.contents[2].text
				the_list['type']=HTTP_READ
				add_to_db(URLS_REQUESTED,the_list)
	con.commit()

if __name__=="__main__":
	main()
