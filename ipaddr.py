import re
import ipaddress
import dns.resolver

from collections import namedtuple
from errbot import BotPlugin, botcmd, cmdfilter

_IP_API = 'origin.asn.cymru.com'
_ASN_API = 'asn.cymru.com'

OriginReply = namedtuple('OriginReply', 'asn subnet country issuer registry_date')
ASReply = namedtuple('ASReply', 'asn country issuer registry_date registrant')

def ip2asn(ip):
	'''Lookup an IP address in Team Cymru's IP ASN database.'''
	reverse_ip = '.'.join(reversed(ip.split('.')))
	try:
		answers = dns.resolver.query('%s.%s' % (reverse_ip, _IP_API), 'TXT')
	except dns.resolver.NXDOMAIN:
		return 'Invalid IP or IP not found.'
	answer = answers[0].to_text().strip('"')
	ip_answer = OriginReply(*[field for field in answer.split(' |')])
	#self.log.info('received answer: %s' % (ip_answer))

	try:
		answers = dns.resolver.query('AS%s.%s' % (ip_answer.asn, _ASN_API), 'TXT')
	except dns.resolver.NXDOMAIN:
		return 'Error occurred on ASN lookup.'
	answer = answers[0].to_text().strip('"')
	asn_answer = ASReply(*[field for field in answer.split(' |')])
	#self.log.info('received answer: %s' % (asn_answer))
	return '''
	```
	Subnet: 		%s
	Registrant: 	%s
	AS:				%s
	Country: 		%s
	Issuer: 		%s
	Registry Date: 	%s
	```
	''' % (ip_answer.subnet, 
		asn_answer.registrant,
		ip_answer.asn,
		ip_answer.country,
		ip_answer.issuer,
		ip_answer.registry_date)

class IPMatch(BotPlugin):
	'''Plugin that finds IP addresses inside of messages and then performs
	lookups and actions based on the presence of an IP.
	'''
	def __init__(self, bot):
		super().__init__(bot)

		self.pattern = re.compile('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

		self._private_networks = [
        ipaddress.IPv4Network('0.0.0.0/8'),
        ipaddress.IPv4Network('10.0.0.0/8'),
        ipaddress.IPv4Network('127.0.0.0/8'),
        ipaddress.IPv4Network('169.254.0.0/16'),
        ipaddress.IPv4Network('172.16.0.0/12'),
        ipaddress.IPv4Network('192.168.0.0/16'),
        ipaddress.IPv4Network('255.255.255.255/32'),
        ]

	def callback_message(self, msg):
		'''Check the messages if they contain an IP address.'''
		user = "@%s" % (msg.frm.username)
		if user == str(self.bot_identifier):
			return

		# Match for IP patterns inside of the message to determine if lookups
		# should be performed
		for match in self.pattern.finditer(msg.body):
			try:
				ip = ipaddress.ip_address(match.group(0))
			except ValueError:
				continue

			# If the ip is in a private address space, skip it.
			for network in self._private_networks:
				if ip in network:
					continue

			self.send(msg.to, 'Found IP Address: %s' % (ip))
			self.send(msg.to, ip2asn(str(ip)))
		return