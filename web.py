#!/usr/bin/python

# -*- coding: utf-8 -*-
import sys, os
import tornado.ioloop
import tornado.web
import logging
import logging.handlers
import re
from urllib import unquote

import xml.etree.ElementTree as ET



import config
import pdb
import hashlib
import time
import urllib2
import json
import web


def deamon(chdir = False):
	try:
		if os.fork() > 0:
			os._exit(0)
	except OSError, e:
		print 'fork #1 failed: %d (%s)' % (e.errno, e.strerror)
		os._exit(1)

def init():
	pass

class DefaultHandler(tornado.web.RequestHandler):
	def get(self):
		self.write('WeChatAPI Say Hello!')

class TestHandler(tornado.web.RequestHandler):
	def get(self):
		self.write('WeChatAPI Test!')

class LogHandler(tornado.web.RequestHandler):
	def get(self):
		log_filename = 'logs/logging'
		if not os.path.exists(log_filename):
			self.write('The log file is empty.')
			return
		log_file = None
		log_file_lines = None
		try:
			log_file = open(log_filename, 'r')
			if log_file is None:
				raise Exception('log_file is None')
			log_file_lines = log_file.readlines()
			if log_file_lines is None:
				raise Exception('log_file_lines is None')
		except Exception, e:
			logger = logging.getLogger('web')
			logger.error('Failed to read the log file (logs/logging), error: %s' % e)
		finally:
			if log_file is not None:
				log_file.close()
		if log_file_lines is None:
			self.write('Failed to read the log file.')
		line_limit = 500
		for _ in log_file_lines[::-1]:
			line_limit -= 1
			if line_limit > 0:
				self.write(unquote(_) + '<BR/>')


	
	
class weixin(tornado.web.RequestHandler):

	def get(self):
		signature = self.get_argument('signature','')
		timestamp = self.get_argument('timestamp','')
        	nonce = self.get_argument('nonce','')
        	echostr = self.get_argument('echostr','')
		
		token="liuzhiqiang"
		list=[token,timestamp,nonce]
        	list.sort()
		sha1=hashlib.sha1()
       	 	map(sha1.update,list)
		hashcode=sha1.hexdigest()
        	if hashcode == signature:
            		self.write(echostr)
        	else:
 
           		self.write('shibai 4055555')
	
	def parse_request_xml(self,rootElem):
        	msg = {}
        	if rootElem.tag == 'xml':
            		for child in rootElem:
				msg[child.tag] = child.text
		return msg
	def post(self):
                body = self.request.body
                msg = self.parse_request_xml(ET.fromstring(body))
                MsgType = tornado.escape.utf8(msg.get("MsgType"))
        	Content= tornado.escape.utf8(msg.get("Content"))
        	FromUserName = tornado.escape.utf8(msg.get("FromUserName"))
        	CreateTime = tornado.escape.utf8(msg.get("CreateTime"))
        	ToUserName = tornado.escape.utf8(msg.get("ToUserName"))
        	if MsgType == "event":
			Content="44444444444444"
		
		if MsgType == "text":
			Content=u"rrrrrrrrrrrrrrrrrrr中文".encoding('utf-8')
		if MsgType == "image":
			Content="tttttttttttttttttttt"
		if MsgType == "voice":
			Content="yyyyyyyyyyyyyyyyyyyyyyy"
		if MsgType == "video":

			Content="pppppppppppppppppp"
		if MsgType == "shortvideo":
			Content="xxxxxxxxxxxxxxxxxxx"
		if MsgType == "location":

			Content="wwwwwwwwwwwwwwwwwwwwwww"
		if MsgType =="link":
			Content="llllllllllllllllllllll"

		if not Content:
			Content="4333333333333333"


                data = """<xml>
                        <ToUserName><![CDATA[%s]]></ToUserName>
                        <FromUserName><![CDATA[%s]]></FromUserName>
                        <CreateTime>%s</CreateTime>
                        <MsgType><![CDATA[%s]]></MsgType>
                        <Content><![CDATA[%s]]></Content>
                </xml>""" % (FromUserName,ToUserName,int(time.time()),'text',Content)
		self.write(data)
	


		
	def token(requset):
                pdb.set_trace()
                url = 'https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=%s&secret=%s' % (
                Config.AppID, Config.AppSecret)
                result = urllib2.urlopen(url).read()
                Config.access_token = json.loads(result).get('access_token')
                print 'access_token===%s' % Config.access_token
                return HttpResponse(result)

	def createMenu(request):
                url = "https://api.weixin.qq.com/cgi-bin/menu/create?access_token=%s" % Config.access_token
                data = {
                        "button":[
                                {
                                        "type":"click",
                                        "name":"111",
                                        "key":"100000010"
                                },
                                {
                                        "name":"000",
                                        "sub_button":[
                                        {
                                                "type":"view",
                                                "name":"222",
                                                "url":"http://user.qzone.qq.com/577142965"
                                        },
                                        {
                                                "type":"view",
                                                "name":"444",
                                                "url":"http://www.baidu.com/"
                                        }]
                                }
                        ]
                }
		
		
                req = urllib2.Request(url)
                req.add_header('Content-Type', 'application/json')
                req.add_header('encoding', 'utf-8')
                response = urllib2.urlopen(req, json.dumps(data,ensure_ascii=False))
                result = response.read()
                return HttpResponse(result)

		
settings = {
	"static_path": os.path.join(os.path.dirname(__file__), "static"),
}

routes = [
	(r"/", DefaultHandler),
	(r"/wx/test", TestHandler),
	(r"/wx/weixin", weixin),
]

if config.Mode == 'DEBUG':
	routes.append((r"/log", LogHandler))

application = tornado.web.Application(routes, **settings)

if __name__ == "__main__":
	if '-d' in sys.argv:
		deamon()
	logdir = 'logs'
	if not os.path.exists(logdir):
		os.makedirs(logdir)
	fmt = '%(asctime)s - %(filename)s:%(lineno)s - %(name)s - %(message)s'
	formatter = logging.Formatter(fmt)
	handler = logging.handlers.TimedRotatingFileHandler(
		'%s/logging' % logdir, 'M', 20, 360)
	handler.suffix = '%Y%m%d%H%M%S.log'
	handler.extMatch = re.compile(r'^\d{4}\d{2}\d{2}\d{2}\d{2}\d{2}')
	handler.setFormatter(formatter)
	logger = logging.getLogger('web')
	logger.addHandler(handler)
	if config.Mode == 'DEBUG':
		logger.setLevel(logging.DEBUG)
	else:
		logger.setLevel(logging.ERROR)

	init()

	application.listen(80)
	print 'Server is running, listening on port 80....'
	tornado.ioloop.IOLoop.instance().start()
