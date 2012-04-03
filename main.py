#!/usr/bin/env python

"""
Standard directory structure:

--> users (all first level users)
   --> username
       --> public
           --> cert.crl (user certificare revocation list)
           --> cert.crt (user cert)
       --> private
           --> cert.key (user private key)
       --> conf
           --> openssl.conf (configuration file for requests)
           --> username / usermail (name and mail, used to streamline end certs requests)
           --> index
           --> serial
       --> certs
           --> end-cert name
               --> cert.crt (end certificate)
               --> cert.key (end private key)

--> cadir (hosting root cert for checking)

--> crls (third parties crls, for checking received files)

--> root-CA (root CA)
    --> private
        --> root.pem
    --> public
        --> root.pem
        --> root-crl.pem

"""

# IMPORTS --------------------------------------------------------------------------------

import sys, os, subprocess, re, time

# GLOBAL CONFIGURATION -------------------------------------------------------------------

CONFIG = {}
CONFIG['root_available'] = False
CONFIG['root_dir'] = "root-ca"
CONFIG['root_conf'] = os.path.join(CONFIG['root_dir'], "conf/openssl.cnf")
CONFIG['users_dir'] = "users"
CONFIG['certs_dir'] = "certs"
CONFIG['crls_dir'] = "crls"
CONFIG['ca_dir'] = "cadir"

# GENERIC FUNCTIONS ----------------------------------------------------------------------

def readFixedLengthInput(length, text, default = "",):
	while 1:
		reading = readInput(text, default)
		if (len(reading) != length):
			print("Input length must be %i"%length)
		else:
			return reading	

def readNotNullInput(text, default = ""):
	while 1:
		reading = readInput(text, default)
		if (len(reading) == 0):
			print("Empty input not allowed")
		else:
			return reading

def readInput(text, default = ""):
	reading = raw_input(text + " [" + default + "]: ")
	if (len(reading) == 0):
		return default
	else:
		return reading

def runCommand(command, output = 0):
	print "--> " + command
	status = []
	p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	for line in p.stdout.readlines():
	    status.append(line)
	retval = p.wait()
	
	if (retval != 0):
		print("\nAn error occured, see output:\n")
		for line in status:
			print line,
		return 1
	
	if (output == 1):
		for line in status:
			print "--> " + line,
	
	return 0

def selectUserDir():

	global CONFIG

	while 1:
		userCertsList = []
		index = 1
	
		print("\nUser certificates:")
		for name in os.listdir(CONFIG['users_dir']):
			path = os.path.join(CONFIG['users_dir'], name)
			if (os.path.isdir(path)):
				print("-> " + name)
			
			cert = os.path.join(path, "public", "cert.crt")
			if (os.path.isfile(cert)):
				print("   %i -> "%index + cert)
				userCertsList.append([index, name])
				index = index + 1
			
		print("")
		
		selection = raw_input("Insert a cert number to select (0 to exit): ")
	
		if (selection == "" or selection == "0"):
			return ""
		try:
			selection = int(selection)
		except:
			continue
		
		if (selection <= len(userCertsList)):
				return os.path.join(CONFIG['users_dir'], userCertsList[selection-1][1])


def selectUserSubdir(USERDIR):

	global CONFIG

	while 1:
		userCertsList = []
		index = 1
	
		print("\nUser certificates:")
		subcertsdir = os.path.join(USERDIR, CONFIG['certs_dir'])
		for name in os.listdir(subcertsdir):
			path = os.path.join(subcertsdir, name)
			if (os.path.isdir(path)):
				print("-> " + name)
			
			cert = os.path.join(path, "cert.crt")
			if (os.path.isfile(cert)):
				print("   %i -> "%index + cert)
				userCertsList.append([index, name])
				index = index + 1
			
		print("")
		
		selection = raw_input("Insert a cert number to select (0 to exit): ")
	
		if (selection == "" or selection == "0"):
			return ""
		try:
			selection = int(selection)
		except:
			continue
		
		if (selection <= len(userCertsList)):
				return os.path.join(USERDIR, CONFIG['certs_dir'], userCertsList[selection-1][1])
		

# CREATION OF AN USER --------------------------------------------------------------------

def createUserCert(USERDIR):

	global CONFIG

	USERDIR = os.path.join(CONFIG['users_dir'], USERDIR)
	
	PRIVATEDIR 	= os.path.join(USERDIR, "private")
	PUBLICDIR 	= os.path.join(USERDIR, "public")
	CONFDIR 	= os.path.join(USERDIR, "conf")
	SIGNEDKEYS 	= os.path.join(USERDIR, "signed-keys")
	USERCERTSDIR = os.path.join(USERDIR, CONFIG['certs_dir'])
	
	USERCERT	= os.path.join(PUBLICDIR, "cert.crt")
	USERKEY		= os.path.join(PRIVATEDIR, "cert.key")
	REQTEMP		= os.path.join(USERDIR, "req.tmp")
	USERREQ		= os.path.join(USERDIR, "cert.req")
	USERCONF	= os.path.join(CONFDIR, "openssl.cnf")
	USERNAME	= os.path.join(CONFDIR, "username")
	USERMAIL 	= os.path.join(CONFDIR, "usermail")
	
	# create folder structure for new CA
	
	if (os.path.isdir(USERDIR)):
		print("Directory %s already exists. Aborting."%USERDIR)
		return
	
	print("Building folder structure starting from \"%s\"..."%USERDIR)
	
	os.mkdir(USERDIR)
	os.mkdir(CONFDIR)
	os.mkdir(PUBLICDIR)
	os.mkdir(PRIVATEDIR)
	os.mkdir(SIGNEDKEYS)
	os.mkdir(USERCERTSDIR)
	
	FILE = open(CONFDIR+"/serial","w")
	FILE.write("01")
	FILE.close()
	
	FILE = open(CONFDIR+"/index","w")
	FILE.close()
	
	print("\nCreating private RSA key...")
	runCommand("openssl genrsa -out %s 2048"%(USERKEY))
	
	print("\nCreating configuration file for signing request...")
	
	FILE = open(REQTEMP, "w")
	
	# header section
	header = """
	[ req ]
	default_bits = 2048
	default_md = sha1
	prompt = no 
	distinguished_name = user_ca_distinguished_name
	x509_extensions = v3_ca
	copy_extensions = copy
	
	[ user_ca_distinguished_name ]
	"""
	FILE.writelines(header)
	
	C = readFixedLengthInput(2, "Nation", "IT")
	FILE.write("C = %s\n"%C)
	
	ST = readNotNullInput("State or Province", "Italy")
	FILE.write("ST = %s\n"%ST)
	
	L = readNotNullInput("Locality", "Brescia")
	FILE.write("L = %s\n"%L)
	
	O = readInput("Organization")
	if (len(O) > 0): FILE.write("O = %s\n"%O)
	
	OU = readInput("Organizational Unit")
	if (len(OU) > 0): FILE.write("OU = %s\n"%OU)
	
	CN = readNotNullInput("User name")
	FILE.write("CN = %s\n"%CN)
	
	EM = readNotNullInput("Email address")
	FILE.write("emailAddress = %s\n"%EM)
	
	# footer section
	footer = """
	[ req_attributes ]
	challengePassword = A challenge password
	challengePassword_min = 4
	challengePassword_max = 20
	 
	[ v3_ca ]
	subjectKeyIdentifier=hash
	authorityKeyIdentifier=keyid:always,issuer:always
	basicConstraints = CA:true
	"""
	FILE.writelines(footer)
	
	FILE.close()
	
	# write user name for future use
	FILE = open(USERNAME, "w")
	FILE.write(CN)
	FILE.close()
	
	# write user email for future use
	FILE = open(USERMAIL, "w")
	FILE.write(EM)
	FILE.close()
	
	# Create signing request
	print("\nCreating signing request...")
	runCommand("openssl req -new -config \"%s\" -key \"%s\" -out \"%s\""%(REQTEMP, USERKEY, USERREQ))
	
	# Sign request with root certificate
	print("\nSigning with root certificate...")
	root_conf = CONFIG['root_conf']
	runCommand("openssl ca -batch -config \"%s\" -in \"%s\" -out \"%s\""%(root_conf, USERREQ, USERCERT))
	
	# Print new certificate description
	print("\nThis is the new certificate..")
	runCommand("openssl x509 -noout -text -in \"%s\" -certopt no_extensions -certopt no_pubkey -certopt no_sigdump -nameopt multiline"%USERCERT, 1)
	
	# Checking cert validity versus root cert
	print("\nChecking new cert validity versus root cert...")
	runCommand("openssl verify -CApath \"%s\" \"%s\""%(CONFIG['ca_dir'], USERCERT), 1)
	
	# Creating configuration file for new user
	print("\nCreating configuration file for new user...")
	new_user_conf_default = "config/new_user_conf_default.cnf"
	new_user_conf = USERCONF
	
	with open(new_user_conf_default, "r") as sources:
		lines = sources.readlines()
	
	newlines = []
	for line in lines:
		newlines.append(re.sub('USERDIR', USERDIR, line))
	lines = newlines
	
	with open(new_user_conf, "w") as sources:
		for line in lines:
			sources.write(line)
	
	print("Created configuration file \"%s\""%(new_user_conf))

# CREATION OF A SECONDARY CERT -----------------------------------------------------------

def createSecondaryCert(USERDIR, ENDDIR):

	global CONFIG

	# Create a secondary cert for signing
	print("\nCreating secondary cert for signing...")
	
	USERDIR = os.path.join(CONFIG['users_dir'], USERDIR)
	USERCONF = os.path.join(USERDIR, "conf", "openssl.cnf")
	USERCERT = os.path.join(USERDIR, "public", "cert.crt")
	USERNAME = os.path.join(USERDIR, "conf", "username")
	USERMAIL = os.path.join(USERDIR, "conf", "usermail")
	USERSERIAL = os.path.join(USERDIR, "conf", "serial")
	
	ENDDIR = os.path.join(USERDIR, CONFIG['certs_dir'], ENDDIR)
	ENDKEY = os.path.join(ENDDIR, "cert.key")
	ENDCERT = os.path.join(ENDDIR, "cert.crt")
	ENDREQ = os.path.join(ENDDIR, "cert.req")
	REQTEMP = os.path.join(ENDDIR, "temp.req")
	
	if (os.path.isdir(ENDDIR)):
		print("Directory %s already exists. Aborting."%ENDDIR)
		return
	
	print("\nBuilding folder structure starting from \"%s\"..."%ENDDIR)
	os.mkdir(ENDDIR)
	
	# Creating private key
	print("\nCreating private key...")
	runCommand("openssl genrsa -out \"%s\""%ENDKEY)
	
	# Creating config file for signing request
	print("\nCreating configuration file for signing request...")
	
	if (os.path.isfile(USERNAME)):
		FILE = open(USERNAME, "r")
		default_cn = FILE.read()
		FILE.close()
	else:
		default_cn = ""

	if (os.path.isfile(USERMAIL)):
		FILE = open(USERMAIL, "r")
		default_mail = FILE.read()
		FILE.close()
	else:
		default_mail = ""
	
	FILE = open(REQTEMP, "w")
	
	# header section
	header = """
	[ req ]
	default_bits = 2048
	default_md = sha1
	prompt = no 
	distinguished_name = user_ca_distinguished_name
	x509_extensions = v3_ca
	copy_extensions = copy
	
	[ user_ca_distinguished_name ]
	"""
	FILE.writelines(header)
	
	C = readFixedLengthInput(2, "Nation", "IT")
	FILE.write("C = %s\n"%C)
	
	ST = readNotNullInput("State or Province", "Italy")
	FILE.write("ST = %s\n"%ST)
	
	L = readNotNullInput("Locality", "Brescia")
	FILE.write("L = %s\n"%L)
	
	O = readNotNullInput("Organization (recipient of signed data)")
	FILE.write("O = %s\n"%O)
	
	OU = readInput("Organizational Unit (recipient of signed data)")
	if (len(OU) > 0): FILE.write("OU = %s\n"%OU)
	
	CN = readNotNullInput("User name", default_cn)
	FILE.write("CN = %s\n"%CN)
	
	EM = readNotNullInput("Email address", default_mail)
	FILE.write("emailAddress = %s\n"%EM)
	
	# footer section
	footer = """
	[ req_attributes ]
	challengePassword = A challenge password
	challengePassword_min = 4
	challengePassword_max = 20
	 
	[ v3_ca ]
	subjectKeyIdentifier=hash
	authorityKeyIdentifier=keyid:always,issuer:always
	basicConstraints = CA:true
	"""
	FILE.writelines(footer)
	
	FILE.close()
	
	# setting serial number for new cert from unix epoch
	FILE = open(USERSERIAL, "w")
	hexTimestamp = hex(int(time.time()))[2:]
	if (len(hexTimestamp) % 2 != 0):
		hexTimestamp = "0" + hexTimestamp # somehow, it needs an even string
	FILE.write(hexTimestamp)
	FILE.close()
	
	# Create signing request
	print("\nCreating signing request...")
	status = runCommand("openssl req -new -config \"%s\" -key \"%s\" -out \"%s\""%(REQTEMP, ENDKEY, ENDREQ))
	if (status != 0):
		print("\nError while creating request, aborting...")
		return
	
	# Sign with user certificate
	print("\nSigning with user certificate...")
	status = runCommand("openssl ca -batch -config \"%s\" -in \"%s\" -out \"%s\""%(USERCONF, ENDREQ, ENDCERT))
	if (status != 0):
		print("\nError while signing certificate, aborting...")
		return
	
	# Print new certificate description
	print("\nThis is the new certificate..")
	runCommand("openssl x509 -noout -text -in \"%s\" -certopt no_extensions -certopt no_pubkey -certopt no_sigdump -nameopt multiline"%ENDCERT, 1)
	
	# Verify certificate against user cert and root cert
	print("\nVerifying end cert against user cert and root cert...")
	runCommand("openssl verify -CApath \"%s\" -CAfile \"%s\" \"%s\""%(CONFIG['ca_dir'], USERCERT, ENDCERT), 1)

# SIGNING A FILE -------------------------------------------------------------------------

def signFile(USERDIR, ENDDIR, SOURCEFILE, SIGNEDFILE):

	global CONFIG
	
	USERCERT = os.path.join(USERDIR, "public", "cert.crt")
	ENDKEY = os.path.join(ENDDIR, "cert.key")
	ENDCERT = os.path.join(ENDDIR, "cert.crt")
	
	print("\nSign file with end user key...")
	runCommand("openssl smime -sign -binary -in \"%s\" -signer \"%s\" -inkey \"%s\" -outform PEM -out \"%s\" -certfile \"%s\""%(SOURCEFILE, ENDCERT, ENDKEY, SIGNEDFILE, USERCERT))
	
	print("\nList certificates in signed file...")
	runCommand("openssl pkcs7 -print_certs -noout -in \"%s\""%SIGNEDFILE, 1)
	
	print("\nVerify signed file against root certificate...")
	runCommand("openssl smime -verify -inform PEM -in \"%s\" -CApath \"%s\" -content \"%s\" > new.dat"%(SIGNEDFILE, CONFIG['ca_dir'], SOURCEFILE), 1)
	
# VERIFYING A SIGNED FILE ----------------------------------------------------------------

def verifyFile(SOURCEFILE, SIGNEDFILE, CRLFILE = ""):

	global CONFIG
	
	SIGNERS = "signers.tmp"

	print("\nList certificates in signed file...")
	runCommand("openssl pkcs7 -print_certs -noout -in \"%s\""%SIGNEDFILE, 1)
	
	print("\nVerify signed file against trusted root certificate...")
	runCommand("openssl smime -verify -inform PEM -in \"%s\" -CApath \"%s\" -content \"%s\"> new.dat"%(SIGNEDFILE, CONFIG['ca_dir'], SOURCEFILE), 1)
	
	if (CRLFILE != ""):
		print("\nDumping certificates for validity check..")
		runCommand("openssl pkcs7 -print_certs -in \"%s\" -out \"%s\""%(SIGNEDFILE, SIGNERS), 1)
	
		# split file in different certs
		print("Splitting dumped certificates in single elements for checking..")
		FILE = open(SIGNERS, 'r')
		line = FILE.readline()
		allCerts = ""
		
		STARTSTRING = "BEGIN CERTIFICATE"
		ENDSTRING = "END CERTIFICATE"
		fileprefix = "cert"
		fileindex = 0
		NEWFILE = None
		
		while line:
			
			if (STARTSTRING in line):
				newfilepath = os.path.join("tmp", "%s%i"%(fileprefix, fileindex))
				print("Writing %s.."%newfilepath)
				NEWFILE = open(newfilepath, 'w')
				NEWFILE.write(line)
				allCerts =  allCerts + "\"" + newfilepath + "\" "
			elif (ENDSTRING in line):
				NEWFILE.write(line)
				NEWFILE.close()
				NEWFILE = None
				fileindex = fileindex + 1

				#print("\nList certificates in signed file...")
				runCommand("openssl x509 -issuer -subject -noout -in \"%s\""%os.path.join("tmp", "%s%i"%(fileprefix, fileindex-1)), 1)

			else:
				if (NEWFILE != None):
					NEWFILE.write(line)
			
			line = FILE.readline()		
		
		print("Done.")
		FILE.close()	
	
		#print("\nList certificates in signed file...")
		#runCommand("openssl x509 -text -noout -in \"%s\""%SIGNERS, 1)		
	
		print("\nVerifying signer's certificate against available CRLs...")
		result = runCommand("openssl verify -verbose -CRLfile \"%s\" -CAfile \"%s\" -CApath \"%s\" -crl_check_all %s"%(CRLFILE, SIGNERS, CONFIG['ca_dir'], allCerts), 1)

# CREATE A CRL ----------------------------------------------------------------------------

def createCRL(USERDIR):

	global CONFIG
	
	USERCONF = os.path.join(USERDIR, "conf", "openssl.cnf")
	USERCERT = os.path.join(USERDIR, "public", "cert.crt")
	USERKEY = os.path.join(USERDIR, "private", "cert.key")
	USERCRL = os.path.join(USERDIR, "public", "cert.crl")
	
	print("\nCreating CRL list:")
	runCommand("openssl ca -gencrl -config \"%s\" -keyfile \"%s\" -cert \"%s\" -out \"%s\""%(USERCONF, USERKEY, USERCERT, USERCRL))
	
	print("\nPrinting CRL:")
	runCommand("openssl crl -in \"%s\" -noout -text "%(USERCRL), 1)
	
# CREATE A CRL ----------------------------------------------------------------------------

def printCRL(USERDIR):

	global CONFIG
	
	USERCRL = os.path.join(USERDIR, "public", "cert.crl")
	
	print("\nPrinting CRL:")
	runCommand("openssl crl -in \"%s\" -noout -text "%(USERCRL), 1)


# REVOKE A CERT --------------------------------------------------------------------------

def revokeCert(USERDIR, ENDDIR):

	global CONFIG
	
	USERCONF = os.path.join(USERDIR, "conf", "openssl.cnf")
	USERCERT = os.path.join(USERDIR, "public", "cert.crt")
	USERKEY = os.path.join(USERDIR, "private", "cert.key")
	USERCRL = os.path.join(USERDIR, "public", "cert.crl")
	
	ENDKEY = os.path.join(ENDDIR, "cert.key")
	ENDCERT = os.path.join(ENDDIR, "cert.crt")
	ENDREQ = os.path.join(ENDDIR, "cert.req")
	REQTEMP = os.path.join(ENDDIR, "temp.req")
	
	print("\nRevoking cert...")
	runCommand("openssl ca -config \"%s\" -revoke \"%s\" -keyfile \"%s\" -cert \"%s\""%(USERCONF, ENDCERT, USERKEY, USERCERT))

	print("\nCreating CRL list:")
	runCommand("openssl ca -gencrl -config \"%s\" -keyfile \"%s\" -cert \"%s\" -out \"%s\""%(USERCONF, USERKEY, USERCERT, USERCRL))
	
	print("\nPrinting CRL:")
	runCommand("openssl crl -in \"%s\" -noout -text "%(USERCRL), 1)

# CHECK AN USER'S CERTS ------------------------------------------------------------------

def checkCerts(USERDIR):
	
	global CONFIG
	
	USERCERT = os.path.join(USERDIR, "public", "cert.crt")
	USERCRL = os.path.join(USERDIR, "public", "cert.crl")
	CHAIN = os.path.join(USERDIR, "chain.tmp")
	
	print("Creating chain with CRL, user cert...")
	print("Chaining \"%s\", \"%s\" into \"%s\""%(USERCERT, USERCRL, CHAIN))
	if (os.path.isfile(USERCRL)):
		print("\nChecking CRL correctness..")
		runCommand("openssl crl -CAfile \"%s\" -in \"%s\" -noout"%(USERCERT, USERCRL), 1)
		
		file(CHAIN,'w').write(file(USERCERT,'r').read() + file(USERCRL,'r').read())
		option = "-crl_check"
	else:
		print("\nNo CRL available for selected user, ignoring CRL check")
		file(CHAIN,'w').write(file(USERCERT,'r').read())
		option = ""

	subcertpath = os.path.join(USERDIR, CONFIG['certs_dir'])
	for subdir in os.listdir(subcertpath):
		if (os.path.isdir(os.path.join(subcertpath, subdir))):
			subcert = os.path.join(subcertpath, subdir, "cert.crt")
			if (os.path.isfile(subcert)):
				print("\nChecking subcert: %s"%subdir)
				result = runCommand("openssl verify -CApath \"%s\" -CAfile \"%s\" %s \"%s\""%(CONFIG['ca_dir'], CHAIN, option, subcert), 1)
	
	if (option == ""):
		print("\nControl terminated, but remember no check has been made about revocation of certificates.")

# TESTING --------------------------------------------------------------------------------

if (os.path.isdir(CONFIG['root_dir'])):
	CONFIG['root_available'] = True

while 1:
	
	curDir = os.path.basename(os.path.dirname(os.path.realpath(__file__)))
	
	print("")
	print("----------------------------------------------")
	print("CA management software")
	print("(c) mario.piccinelli@ing.unibs.it")
	print("Current directory: %s"%curDir)
	print("----------------------------------------------")
	print("1  - Create new user")
	print("2  - Create end certificate")
	print("3  - List users")
	print("---- signature management --------------------")
	print("4  - Sign a file")
	print("5  - Verify a signature")
	print("---- crl management --------------------------")
	print("6  - Create user CRL")
	print("7  - Print user CRL")
	print("8  - Revoke a certificate")
	print("9  - Check an user's certificates")
	print("---- third party files -----------------------")
	print("10 - chech a received file")
	print("     against root cert and available CRLs")
	print("----------------------------------------------")
	print("0 - quit")
	print("")
	selection = raw_input("Select action [0]: ")
	
	if ((selection == "") or (selection == "0")):
		sys.exit(0)
	
	# Create new user	
	if (selection == "1"):
		if (CONFIG['root_available'] == False):
			print("\nRoot cert not available, unable to create new users.")
		else:
			USERDIR = raw_input("Insert the name of the new user to create: ")
			if (len(USERDIR) == 0): continue
			createUserCert(USERDIR)	
	
	# Create new end cert
	if (selection == "2"):
	
		userCertsList = []
		index = 1
	
		print("\nUser certificates:")
		for name in os.listdir(CONFIG['users_dir']):
			path = os.path.join(CONFIG['users_dir'], name)
			if (os.path.isdir(path)):
				print("-> " + name)
			
			cert = os.path.join(path, "public", "cert.crt")
			if (os.path.isfile(cert)):
				print("   %i -> "%index + cert)
				userCertsList.append([index, name])
				index = index + 1
			
		print("")
		
		selection = raw_input("Insert a cert number to select (0 to exit): ")
	
		if (selection == "" or selection == "0"):
			continue
		try:
			selection = int(selection)
		except:
			continue
		
		if (selection <= len(userCertsList)):
				USERDIR = userCertsList[selection-1][1]
	
		print("Selected user: %s"%USERDIR)
	
		ENDDIR = raw_input("Name of the secondary cert:")
		if (len(ENDDIR) == 0): continue
		
		createSecondaryCert(USERDIR, ENDDIR)
		
	# list users
	if (selection == "3"):
		
		while (1):
			userCertsList = []
			index = 1
		
			print("\nUser certificates available:")
			for name in os.listdir(CONFIG['users_dir']):
				path = os.path.join(CONFIG['users_dir'], name)
				if (os.path.isdir(path)):
					print("-> " + name)
				else:
					continue
				
				cert = os.path.join(path, "public", "cert.crt")
				if (os.path.isfile(cert)):
					print("   %i -> "%index + cert)
					userCertsList.append([index, cert])
					index = index + 1
				
				subcertpath = os.path.join(path, CONFIG['certs_dir'])
				for subdir in os.listdir(subcertpath):
					if (os.path.isdir(os.path.join(subcertpath, subdir))):
						subcert = os.path.join(subcertpath, subdir, "cert.crt")
						if (os.path.isfile(subcert)):
							print("        %i -> %s"%(index, subcert))
							userCertsList.append([index, subcert])
							index = index + 1
				
			print("")
			
			selection = raw_input("Insert a cert number to see description (0 to exit): ")
		
			if (selection == "" or selection == "0"):
				break

			try:
				selection = int(selection)
			except:
				print("no int")
				continue
			
			if (selection <= len(userCertsList)):
				runCommand("openssl x509 -noout -text -in \"%s\" -certopt no_extensions -certopt no_pubkey -certopt no_sigdump -nameopt multiline"%userCertsList[selection-1][1], 1)	
			else:
				print("Index out")
	
	# sign a file (detached signature)
	if (selection == "4"):
		USERDIR = selectUserDir()
		if (len(USERDIR) == 0):
			continue
		
		ENDDIR = selectUserSubdir(USERDIR)
		if (len(ENDDIR) == 0):
			continue
		
		SOURCEFILE = raw_input("File to sign: ")
		if (len(SOURCEFILE) == 0):
			continue
		
		if (os.path.isfile(SOURCEFILE) == False):
			print("\nThe file doesn't exist")
			continue
		
		sourceFileName = os.path.splitext(SOURCEFILE)[0]
		SIGNEDFILE = sourceFileName + ".p7m"
		
		print("Signature data in: " + SIGNEDFILE)
		
		signFile(USERDIR, ENDDIR, SOURCEFILE, SIGNEDFILE)
		
	# Verify a signature
	if (selection == "5"):
		
		SOURCEFILE = raw_input("Original to verify: ")
		if (len(SOURCEFILE) == 0):
			continue
		
		if (os.path.isfile(SOURCEFILE) == False):
			print("\nThe file doesn't exist")
			continue
		
		sourceFileName = os.path.splitext(SOURCEFILE)[0]
		SIGNEDFILE = sourceFileName + ".p7m"
		
		print("Signature data in: " + SIGNEDFILE)	
		
		if (os.path.isfile(SIGNEDFILE) == False):
			print("\nThe signature %s file doesn't exist"%(SIGNEDFILE))
			continue
		
		verifyFile(SOURCEFILE, SIGNEDFILE)

	# create crl
	if (selection == "6"):
	
		USERDIR = selectUserDir()
		if (len(USERDIR) == 0):
			continue

		createCRL(USERDIR)

	# print crl
	if (selection == "7"):
	
		USERDIR = selectUserDir()
		if (len(USERDIR) == 0):
			continue

		printCRL(USERDIR)
	
	# revoke certificate
	if (selection == "8"):
		
		USERDIR = selectUserDir()
		if (len(USERDIR) == 0):
			continue
		
		ENDDIR = selectUserSubdir(USERDIR)
		if (len(ENDDIR) == 0):
			continue
			
		revokeCert(USERDIR, ENDDIR)
		
	# check certs
	if (selection == "9"):
	
		USERDIR = selectUserDir()
		if (len(USERDIR) == 0):
			continue

		checkCerts(USERDIR)
	
	# Verify an externally signed file with stored CRLs
	if (selection == "10"):
		
		CRLDIR = CONFIG['crls_dir']
		CHAIN = "chain.tmp"
		
		# clear chain file
		FILE = open(CHAIN, "w")
		FILE.write("")
		FILE.close()
		
		# create a chain file with all crls
		print("\nChaining %i CRLs from %s..."%(len(os.listdir(CRLDIR)), CRLDIR))
		for element in os.listdir(CRLDIR):			
			FILE = open(CHAIN, "a")
			FILE.write(open(os.path.join(CRLDIR, element)).read())
			runCommand("openssl crl -issuer -lastupdate -nextupdate -noout -in \"%s\""%os.path.join(CRLDIR, element), 1)
			FILE.close()
		
		# checking file
		SOURCEFILE = raw_input("\nOriginal to verify [data.dat]: ")
		if (len(SOURCEFILE) == 0):
			SOURCEFILE = "data.dat"
		
		if (os.path.isfile(SOURCEFILE) == False):
			print("\nThe file doesn't exist")
			continue
		
		sourceFileName = os.path.splitext(SOURCEFILE)[0]
		SIGNEDFILE = sourceFileName + ".p7m"
		
		print("Signature data in: " + SIGNEDFILE)	
		
		if (os.path.isfile(SIGNEDFILE) == False):
			print("\nThe signature %s file doesn't exist"%(SIGNEDFILE))
			continue
		
		verifyFile(SOURCEFILE, SIGNEDFILE, CHAIN)










