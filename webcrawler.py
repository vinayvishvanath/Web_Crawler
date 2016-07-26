import socket
import sys
import re
import urlparse
from bs4 import BeautifulSoup
CRLF = "\r\n"
flag_count=0
flaglist=[]

username=sys.argv[1]
password=sys.argv[2]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
	host = 'cs5700sp16.ccs.neu.edu'
	port = 80
	remote = socket.gethostbyname( host )
	s.connect((host, port))
#print 'Connected'
	request=("GET /accounts/login/?next=/fakebook/ HTTP/1.0\r\n"
        	 "Host: cs5700sp16.ccs.neu.edu\r\n"
         	"Connection: keep-alive\r\n"
         	"\r\n"
         	)
	#print request
	s.sendall(request)
except socket.error:
	print 'SOCKET ERROR'
        sys.exit()
d =s.recv(4096)
if 'Content-Length: 0' not in d:
	while '</html>' not in d: 
		d=d+ s.recv(4096)
#print d
#d =response.decode()
csrf_token1=d[245:277]
#print csrf_token1
#print(type(csrf_token1))
#a=response.find('sessionid')
#print a
sessionid=d[366:398]
#print sessionid
#print "csrfmiddlewaretoken="+csrf_token1+"username=001773693&password=WZMSZ1TU&next=/fakebook/\r\n"
#print(len('csrfmiddlewaretoken='+csrf_token1+'&username=001773693&password=WZMSZ1TU&?next=/fakebook/\r\n'))

request_post=(
           'POST /accounts/login/ HTTP/1.0 \r\n'
           'Host: cs5700sp16.ccs.neu.edu\r\n'
           'Connection: keep-alive\r\n'
           'Content-Length: 108\r\n'
           'Origin: http://cs5700sp16.ccs.neu.edu\r\n'
           'Content-Type: application/x-www-form-urlencoded\r\n'
           'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n'
           'Referer: http://cs5700sp16.ccs.neu.edu/accounts/login/?next=/fakebook/\r\n'
           'Accept-Encoding: gzip, deflate\r\n'
           'Cookie: csrftoken=' + csrf_token1 + '; sessionid=' +sessionid+'\r\n'
           '\r\n'
           'csrfmiddlewaretoken='+csrf_token1+'&username='+username+'&password='+password+'&?next=/fakebook/\r\n'
)
#print request_post
#s.sendall(request_post)
response_post=''
while '302 FOUND' not in response_post:
	s.sendall(request_post)
	response_post=s.recv(4096)
#if 'Content-Length: 0' not in response_post:
 #       while '</html>' not in response_post:
  #              response_post=response_post + s.recv(4096)
#print response_post
#a1=response_post.find('sessionid')
#print a1
sessionid1=response_post[248:280]
#print sessionid1

#d1=request_post.find('/fakebook/')
#print d1

request1=request_post[329:339]
#print request1

redirect_request=("GET " +request1+ " HTTP/1.0\r\n"
        "Host: cs5700sp16.ccs.neu.edu\r\n"
        "Connection: keep-alive\r\n"
        "Referer: http://cs5700sp16.ccs.neu.edu/accounts/login/?next=/fakebook/\r\n"
        "Cookie: csrftoken=" + csrf_token1 +"; sessionid=" + sessionid1 +"\r\n"
        "\r\n"

)
#print redirect_request
s.sendall(redirect_request)
redirect_response=s.recv(4096)
if 'Content-Length: 0' not in redirect_response:
 	while '</html>' not in redirect_response:
 		redirect_response=redirect_response+s.recv(4096)
#print redirect_response
l=[]
x=[]
s.close()
soup= BeautifulSoup(redirect_response, 'html.parser')
for link in soup.find_all('a'):
                              bu=link.get('href')
                              #print bu
                              l.append(str(bu).encode('utf-8'))
                              x.append(str(bu).encode('utf-8'))

unwanted=[]
#unwanted.append(l[0])
unwanted.append(l[-3:])
#del l[0]
del l[-3:]
del x[-3:]
def get_request(req):

        req1=('GET ' +req+ ' HTTP/1.0\r\n'
              'Host: cs5700sp16.ccs.neu.edu\r\n'
              'Connection: keep-alive\r\n'
              'Referer: http://cs5700sp16.ccs.neu.edu/accounts/login/?next=/fakebook/\r\n'
              'Cookie: csrftoken=' + csrf_token1 + '; sessionid=' +sessionid1+'\r\n'
              '\r\n'
              )
        #print req1
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		host = 'cs5700sp16.ccs.neu.edu'
		port = 80
		remote = socket.gethostbyname( host )
		s.connect((host, port))
        	s.sendall(req1)
	except socket.error:
		print 'SOCKET ERROR'
		sys.exit()
        resp1=s.recv(4096)
        if 'Content-Length: 0' not in resp1:
		while '</html>' not in resp1:
			resp1=resp1+s.recv(4096)
        		if 'Connection: close' in resp1:
                           break
        if '500' in resp1:
              s.sendall(req1)
              resp1=s.recv(4096)
        #print resp1
        s.close()
        global flag_count
        soup= BeautifulSoup(resp1, 'html.parser')
        for link in soup.find_all('a'):
                              bu=link.get('href')
                              #print bu
                              c=(str(bu).encode('utf-8'))
                              if (c!='/fakebook/') and (c not in l) :
                                #print 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC',len(c)
                                l.append(c)
                                x.append(c)
                                #print'XXXXX',x
                                #print'LLLLL',l
        p = str(soup.find('h2', attrs={'class': 'secret_flag'}))
        if(p != 'None'):
            flag=p[47:112]
            #print 'FLAGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG',flag
        if flag not in flaglist:
                flaglist.append(flag)
                flag_count = flag_count+1
                print flag
        if(flag_count == 5):
             #print 'flaglist',flaglist
             #for k in flaglist:
                #print k
                sys.exit()

#print 'l =*********************************************************************** ',l,'length = ',len(l)
flag_count=0
secondlist=[]
while True:
        secondlist=x[:]
        #print 'SECOND LIST',secondlist
        x=[]
	for i in range(len(secondlist)):
           	url=secondlist[i]
           	#print url
           	get_request(url)
                print 'LENGTHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH',len(l)
               

                     
