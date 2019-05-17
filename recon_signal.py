# -*- coding: utf-8 -*-
"""
Created on Sat Mar 18 12:00:17 2017

@author: Josh Kaggie
"""




DEBUG = True

optionfile = 'recon.opts'


from reconlibs import *  #

import socket
import sys



HOSTNAME, SIGPORT, USERNAME, PASSWORD, SSHPORT, MRRAW, RECON_FILEPATH, RECONSCRIPT, RECON_DICOM_DIR,  SCANNER_DICOM_DIR, LOGFILE, opts = readoptions(optionfile)


print 'Signalling recon server to reconstruct'
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOSTNAME,SIGPORT))
client.send(args_to_str(sys.argv))   ##  MESSAGE TO SEND TO SERVER, BASICALLY FILES THAT ARE INPUT


print sys.argv
echo = capture_packet_client(client)
print echo


if '-quit' in sys.argv:
    client.send('QUIT')
        

client.close()


















