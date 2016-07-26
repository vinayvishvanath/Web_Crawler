import socket
import random
from struct import *
import time
import subprocess
import sys 
import os
from urlparse import urlparse
import urllib2

iptables_flush="sudo iptables -F"
os.system(iptables_flush)
iptables_command="sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP"
#print iptables_command
os.system(iptables_command)

global tcp_seq
global time2
global count
global tcp_ack
global tcp_seq1
global tcp_ack1
global file_name
global seq_data
global Tot_data
global w,z,o,p
global tcp_flags
global extrcount
global next_exp_seqnum
global path,file_name
extrcount=0
buffereddata = {}
z=0.0
w=0.0
o=0
p=0
ackcount=0
global tcp_seq1_list
tcp_seq1_list=[]

seq_data=0
url = sys.argv[1]
#url = 'http://david.choffnes.com/classes/cs4700sp16/project4.php'
if "http://" not in url:
        url = "http://" + url
host = urlparse(url)
hostname=host[1]
path=host[2]
t=path.split('/')[-1:]
if path=='' or path[-1:]=="/":
	file_name='index.html'
else:
	file_name=t[0]
print 'hostname=', hostname
print 'filename=', file_name 
dst_name=socket.gethostbyname(hostname)
dst_ip = socket.inet_aton(dst_name)
#dst_ip=socket.gethostbyname('www.david.choffnes.com')
#print 'D',dst_name
x=subprocess.check_output("ifconfig", shell=True).split()
#print x
try:
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(('8.8.8.8',0))				# Determining Src Ip using Google's DNS
	src_name = s.getsockname()[0]
	#print 'srcip',type(srcip)
	#print 'source ip= srcip=', m
	#print 'dstination ip = dstip=', n
except socket.error , er:
 	print "Socket Creation Error :", er[1]
	sys.exit()
#dst_ip=socket.gethostbyname('www.david.choffnes.com')
#print 'D',dst_name
src_ip = socket.inet_aton(src_name)

#global n
#tcp header fields
source_port=random.randint(10000,65000)
dest_port=80
sequence_number=random.randint(0,65535)

#wnd_size=socket.htons(1000)
wnd_size=65000
tcp_checksum=0
tcp_urg_ptr=0
n=0
global payload
next_exp_seqnum=1

def checksum(inp):
	set= 0
    	# loop taking 2 characters at a time
    	for i in range(0, len(inp), 2):
        	y = ord(inp[i]) + (ord(inp[i+1]) << 8 )
        	set = set + y
	#if checksum contains the carry
    	set = (set>>16) + (set & 0xffff);
    	set = set + (set >> 16);
    #complement and mask to 4 byte short
    	set = ~set & 0xffff
    	return set



def tcp_header(src_ip,dst_ip,source_port,dest_port,data,sequence_number,ack_number,fin,syn,psh,ack,wnd_size=socket.htons(7)):
	urg=0
	rst=0	
	data_offset=5
	tcp_flag=fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5) 
	tcp_offset_reserve=(data_offset << 4) + 0 
	#print 'CHECK',type(source_port)
	tcp_header1=pack('!HHLLBBHHH' , source_port, dest_port, sequence_number, ack_number, tcp_offset_reserve, tcp_flag, wnd_size, 0, 0)
	reserved=0
	urg_ptr=0
	protocol=6
	tcp_length=len(tcp_header1) + len(data)
	psuedo_header=pack('!4s4sBBH',src_ip,dst_ip,reserved,protocol,tcp_length)
	psuedo_header=psuedo_header + tcp_header1 + data
	tcp_checksum=checksum(psuedo_header)
	tcp_header2 = pack('!HHLLBBH' ,source_port,dest_port, sequence_number, ack_number, tcp_offset_reserve, tcp_flag, wnd_size) 	
	tcp_header2 = tcp_header2 + pack('H' , tcp_checksum)	
	tcp_header2 = tcp_header2 + pack('!H' , urg_ptr)
	
	return tcp_header2



def ip_header(ip_proto, ip_ident, src_ip, dst_ip):
	ip_ident=54321
	ip_tos = 0
	ip_len = 0
	ip_ihl_ver = (4 << 4) + 5
	ip_proto = socket.IPPROTO_TCP
	ip_total = pack('!BBHHHBBH4s4s', ip_ihl_ver, 0, 0, ip_ident, 0, 255, ip_proto, 0, src_ip, dst_ip)
	checksum_ip = checksum(ip_total)	
	return pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_len, ip_ident, 0, 255, ip_proto, checksum_ip, src_ip, dst_ip)


#s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
def syn():

	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	#s.bind(('eno16777736', ))
	data=''
	ip_header1=ip_header(socket.IPPROTO_TCP,54321,src_ip,dst_ip)
	tcp_header3=tcp_header(src_ip,dst_ip,source_port,dest_port,data,sequence_number,0,0,1,0,0,wnd_size)
	packet1=ip_header1+tcp_header3+data
	#print packet1
	s.sendto(packet1,(dst_name,0))
	#print 'type x',type(x)
	print 'syn sent'
	#s.close()
	return x
	


def syn_ack(x):
	global tcp_seq
	global tcp_ack
	global dst_port
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	#s.bind((src_name, source_port))
	data = s.recvfrom(65535)
	#print 'type y',type(y)
	data = data[0]
	#packet_loss(x, y)
	#ipheader extraction
	unpack_ipheader=unpack('!BBHHHBBH4s4s' , data[0:20])
	Ip_Ver_Hlen = unpack_ipheader[0] 				# first 8 bits (IP version + Header Length)
	Ip_Ver = Ip_Ver_Hlen >> 4				# shifting 4 bits to right to get IP Version number
	Ip_Hlen = Ip_Ver_Hlen & 0xF				# anding with 0xF to geth the header length
	Ip_Tot_Hlen = Ip_Hlen * 4
	#print 'Ip_Tot_Hlen',Ip_Tot_Hlen
	Ip_totallength=unpack_ipheader[2]
	#print 'IP_total_length_syn_Ack',Ip_totallength
	ip_src=socket.inet_ntoa(unpack_ipheader[8])
	ip_dst=socket.inet_ntoa(unpack_ipheader[9])
	ip_checksum=unpack_ipheader[7]
	#print 'IP_src',ip_src
	#print 'IP_dst',ip_dst
	#tcpheader extraction
	unpack_tcpheader=unpack('!HHLLBBHHH' , data[Ip_Tot_Hlen : Ip_Tot_Hlen+20])
	tcp_seq =unpack_tcpheader[2]					# Sequence Number
	tcp_ack =unpack_tcpheader[3]	
	dst_prt = unpack_tcpheader[1]
	tcp_checksum = unpack_tcpheader[7]
	#print 'flag',unpack_tcpheader[5]
	print 'unpack_tcpheader',unpack_tcpheader
	print 'unpack_ipheader',unpack_ipheader
	########################################################################################################
	TCP_data=data[20:]
	psuedo_header=pack('!4s4sBBH',ip_dst,ip_src,0,socket.IPPROTO_TCP,len(TCP_data))
	TOTAL_TCP= psuedo_header+TCP_data
	checksum1=checksum(TOTAL_TCP)
	if checksum1==0:
		print 'PACKET VALIDATED'
		pass
	else:
		print 'FAIL'
	###########################################################################################################
	s.close()
	return unpack_tcpheader

	
start_time=syn()
unpack_tcpheader=syn_ack(start_time)

def ack():
	global path,hostname
	tcp_seq = unpack_tcpheader[2]					# Sequence Number
	tcp_ack = unpack_tcpheader[3]
	#print 'tcp_seq',tcp_seq
	#print 'tcp_ack',tcp_ack
	s1 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	data=''
	tcp_header4=tcp_header(src_ip,dst_ip,source_port,dest_port,data,tcp_ack,tcp_seq+1,0,0,0,1,wnd_size)
	ip_header2=ip_header(socket.IPPROTO_TCP,54330,src_ip,dst_ip)
	packet2 = ip_header2+ tcp_header4+ data
	s1.sendto(packet2, (dst_name, 0))
	print 'ACK_SENT'
	data1="GET "+path+" HTTP/1.0\r\nHost: "+hostname+"\r\nConnection: keep-alive\r\n\r\n"
			
	#print data1
	if len(data1)% 2 != 0:
		data1 = data1 + " "
	tcp_header5=tcp_header(src_ip,dst_ip,source_port,dest_port,data1,tcp_ack,tcp_seq+1,0,0,1,1,wnd_size)
	ip_header3=ip_header(socket.IPPROTO_TCP,54320,src_ip,dst_ip)
	packet3=ip_header3+ tcp_header5+ data1
	#print 'PACKET3',packet3
	s1.sendto(packet3, (dst_name, 0))
	print 'GET SENT'
	
	
		

ack()

	
##########################################################################################################
def fin(vin,nup):

	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	#s.bind(('eno16777736', ))
	data=''
	ip_header3=ip_header(socket.IPPROTO_TCP,54321,src_ip,dst_ip)
	tcp_header5=tcp_header(src_ip,dst_ip,source_port,dest_port,data,nup,vin,1,0,0,1,wnd_size)
	packet3=ip_header3+tcp_header5+data
	#print packet3
	s.sendto(packet3,(dst_name,0))
	#print 'type x',type(x)
	print 'fin sent'
		


	
	
def extract():
	global a
	global b
	global time2
	global url
	global payload
	global buffererdata
	global Tot_data
	global seq_data
	global tcp_seq1
	global tcp_ack1
	global tcp_flags
	global extrcount
	s_recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

	http=s_recv.recvfrom(65535)
	extrcount+=1
	time2=time.time()  #time data was received
	http=http[0]
	#print 'HTTP',http
	status = http[49:52]
	print status
	if status != '200':
		if status == '301':
			print("This page is moved permanently")
			sys.exit()
		if status == '400':
			print("Bad request")
			sys.exit()
		if status == '404':
			print('Page Not Found')
			sys.exit()
		if status == '500':
			print('internal server error')
			sys.exit()
	
	

	
	unpack_ipheader1=unpack('!BBHHHBBH4s4s' , http[0:20])
	Ip_Ver_Hlen1 = unpack_ipheader1[0] 				# first 8 bits (IP version + Header Length)
	Ip_Ver1 = Ip_Ver_Hlen1 >> 4				# shifting 4 bits to right to get IP Version number
	Ip_Hlen1 = Ip_Ver_Hlen1 & 0xF				# anding with 0xF to geth the header length
	Ip_Tot_Hlen1 = Ip_Hlen1 * 4
	#print 'Ip_Tot_Hlen',Ip_Tot_Hlen1
	Ip_totallength=unpack_ipheader1[2]
	ip_checksum1=unpack_ipheader1[7]
	#print 'IP_total_length',Ip_totallength
	seq_data += Ip_totallength-40		

	ip_src1=socket.inet_ntoa(unpack_ipheader1[8])
	ip_dst1=socket.inet_ntoa(unpack_ipheader1[9])	
	#print 'IP_src1',ip_src1
	#print 'IP_dst1',ip_dst1
	#tcpheader extraction
	unpack_tcpheader1=unpack('!HHLLBBHHH' , http[Ip_Tot_Hlen1 : Ip_Tot_Hlen1+20])
	tcp_seq1 =unpack_tcpheader1[2]
	tcp_seq1_list.append(tcp_seq1)					
	tcp_ack1 =unpack_tcpheader1[3]	
	dst_prt1 = unpack_tcpheader1[1]
	tcp_flags =unpack_tcpheader1[5]
	tcp_Hlen_Res = unpack_tcpheader1[4]					# Total header + Reserved (8 bits)
	tcp_Hlen = tcp_Hlen_Res >> 4
	Tot_Header_Size = Ip_Tot_Hlen1 + tcp_Hlen * 4		# TCP + IP Header (to get payload)
	Tot_data = len(http) - Tot_Header_Size
	payload = http[Tot_Header_Size:]
	
	#print Tot_data
	tcp_checksum1 = unpack_tcpheader1[7]
	#print 'tcp_seq1',tcp_seq1
	#print 'tcp_ack1',tcp_ack1
	#print 'CHECK THE FLAGS',tcp_flags
	print 'unpack_tcpheader1',unpack_tcpheader1
	print 'unpack_ipheader1',unpack_ipheader1
	
	'''if payload !='':
		buffereddata[tcp_seq1] = payload'''
	###########################################################################################################
	'''if next_exp_seqnum==tcp_seq1:
		ack_send(next_exp_seqnum,tcp_ack1)
		next_exp_seqnum=tcp_seq1+Tot_data'''


	'''if tcp_flags ==24:
		ack_send(tcp_seq1,tcp_ack1)
	if tcp_flags ==25:
		fin(tcp_seq1,tcp_ack1)
		makefile(buffereddata)
		iptables_flush="sudo iptables -F"
		os.system(iptables_flush)
		os.system('wget '+ url)
		sys.exit()'''
	return tcp_seq1, tcp_ack1, Tot_data, tcp_flags, payload
				 
def makefile(buffereddata):
			global file_name
			global tcp_seq1_list
			print 'tcp_seq1_list', tcp_seq1_list, len(tcp_seq1_list)
			print buffereddata.keys()
			#test =[]
			ordered_tcp_seq = sorted(buffereddata.keys())
			print 'ordered_tcp_seq', ordered_tcp_seq, len(ordered_tcp_seq)
			abc = open(file_name, "w")
			i = 0
			for k in ordered_tcp_seq:
			    if i == 0:
			    	#print k
			        d = buffereddata[k]
			        #print 'ddddddddddddddddddddd',d
				#--removes HTTP 200 response msg
			        abc.writelines(d.split('\r\n\r\n')[1])
			     	#test.append(d.split('\r\n\r\n')[1])
			        i = i + 1
			    else:
			    	#if buffereddata[k] not in test:
			        abc.writelines(buffereddata[k]) 
			        #test.append(buffereddata[k])

			       
			abc.close()
def ack_send(vin,nup):
	#global a
	#global b
	global seq_data
	global time2
	global ackcount
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	data=''
	tcp_header4=tcp_header(src_ip,dst_ip,source_port,dest_port,data,nup,vin,0,0,0,1,wnd_size)
	ip_header2=ip_header(socket.IPPROTO_TCP,54330,src_ip,dst_ip)
	packet2 = ip_header2+ tcp_header4+ data
	s.sendto(packet2, (dst_name, 0))
	ackcount+=1
	print 'ACK_SENT ACK ACK'

def packet_drop(seq,ack):
	cwnd=1
	sstresh=sstresh/2
	ack_send(seq,ack)



v,w,x,y,z=extract()
next_exp_seqnum=v
time1=time2
while True:
		a,b,c,d,e=extract()
		print a,b,c,d,'RETURN'
		if time2-time1>60.0:
			packet_drop(o,p)
			continue
		if next_exp_seqnum==a:
			o=a+c
			p=b
			buffereddata[a] = e
			if d ==25:
				fin(o+1,p)
				break
			print 'vinay'
			ack_send(a+c,b)
			time1=time.time()
			next_exp_seqnum=a+c
		else:
			#ack_send(o,p)
			print 'nupoor'
		
makefile(buffereddata)
iptables_flush="sudo iptables -F"
os.system(iptables_flush)
print 'ackcount', ackcount
print 'extrcount', extrcount
os.system('wget '+ url)
sys.exit()