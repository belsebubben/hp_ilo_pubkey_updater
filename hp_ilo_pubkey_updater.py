#!/usr/bin/python
import socket, sys
import optparse

# Parsing options
def parse_options():
	''' parsing options '''
	opts = optparse.OptionParser(description='Import hostkey to hp ilo', prog='hp_ilo_keyimporter.py', version='0.1')

	opts.add_option("--host", "-H", help="ilo hostname (ip address)")
	opts.add_option("--sshpubkey", "-s", help="ssh public keyfile")
	opts.add_option("--user", "-u", help="ilo user (both the one to set key for and to login as)", default="Administrator")
	opts.add_option("--password", "-p", help="Ilo password")
	options, arguments = opts.parse_args()

	if not options.host or not options.sshpubkey:
		opts.print_help()
		sys.exit(1)

	if not options.password:
		print "No password provided"
		options.password = raw_input( "Enter password for %s@%s:" % (options.user, options.host) ).strip()

	return opts, options, arguments
# end parsing options


def pubkey_read(options):
	'''try to read in ssh_public key'''
	try:
		sshpubkey = open(options.sshpubkey).read().strip()
		return sshpubkey
	except Exception, err:
		sys.stderr.write('ERROR getting publkickey: %s\n' % str(err))
		opts.print_help()
		sys.exit(1)



def command_formatter(options, sshpubkey):
	xml_command="""
<LOCFG VERSION="2.21" />
<RIBCL VERSION="2.22">
<LOGIN USER_LOGIN="%(user)s" PASSWORD="%(password)s">
<USER_INFO MODE="read">
<GET_USER USER_LOGIN="%(user)s"/>
</USER_INFO>
</LOGIN>
</RIBCL>""" % {'user': options.user, 'password': options.password, 'sshpubkey': sshpubkey}
	return xml_command

def command_formatter(options, sshpubkey):
	xml_command="""
<RIBCL VERSION="2.0">
  <LOGIN USER_LOGIN="%(user)s" PASSWORD="%(password)s">
  <RIB_INFO MODE="write">
    <IMPORT_SSH_KEY>
-----BEGIN SSH KEY-----
%(sshpubkey)s
-----END SSH KEY-----
    </IMPORT_SSH_KEY>
  </RIB_INFO>
  </LOGIN>
</RIBCL>""" % {'user': options.user, 'password': options.password, 'sshpubkey': sshpubkey}
	return xml_command

def ribcommander(options, command):
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	try:
		server.connect((options.host, 443))
	except Exception, err:
		sys.stderr.write('ERROR connecting to host: %s\n' % str(err))
		opts.print_help()
		sys.exit(2)

	ssl_sock = socket.ssl(server)
	ssl_sock.write('<?xml version="1.0"?>\r\n')

	data = ssl_sock.read()
	print data

	ssl_sock.write(command)


	import time

	while 1:
		try:
			time.sleep(2)
			data = data + ssl_sock.read()
		except socket.sslerror:
			break

	print data


# main
if __name__=="__main__":
	opts, options, arguments = parse_options()
	pubkey = pubkey_read(options)
	command = command_formatter(options, pubkey)  # This is the function that should be exchanged in order to accomplish something else
	ribcommander(options, command)
# END
