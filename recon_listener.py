# -*- coding: utf-8 -*-
"""
Created on Fri Mar 17 10:09:14 2017

@author: Josh Kaggie
"""


DEBUG = True
KEEPALIVE = True   #AFTER COMPLETING ONE SERVER RECON, LISTEN FOR NXT
ALLOWQUIT = True   #ALLOW SIGNAL FROM CLIENT TO SHUT DOWN RECON SERVER

optionfile = 'recon.opts'


from reconlibs import *


import socket
import base64
import os
import sys
import traceback


HOSTNAME, SIGPORT, USERNAME, PASSWORD, SSHPORT, MRRAW, RECON_FILEPATH, RECONSCRIPT, RECON_DICOM_DIR,  SCANNER_DICOM_DIR, LOGFILE, opts = readoptions(optionfile)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    server.bind((HOSTNAME, SIGPORT))
except:
    print 'Socket may be in use'
    server.setsockopt(socket.SOCK_STREAM, socket.SO_REUSEADDR, 1)  # BE CAREFUL NOT TO OVERWRITE SOCKETS!
    server.bind((HOSTNAME, SIGPORT))

    

while KEEPALIVE:
    
    print 'Listening for connections...'
    rxbuffer, connection, address = capture_packet(server)
    print 'Connected to ',
    print  address
    print rxbuffer
      
    if DEBUG == 2:
        rxbuffer = "MRFrecon ['1','94720','3' ]"  ##REMOVE THIS, DUMMY CASE
    
    if '-quit' in rxbuffer or rxbuffer == 'QUIT' or rxbuffer == 'EXIT':
        if ALLOWQUIT:
            KEEPALIVE = False
            continue
    
    #print opts
    if 'TRUSTEDIPS:' in opts[0]:
        trustedips = opts[0].split('TRUSTEDIPS:')[1].split('\n')[0].strip().split(',')
        #get_opts_tagvals(opts[0],'TRUSTEDIPS:')
        #print trustedips, len(trustedips)
        if address[0] not in trustedips and trustedips != ['']:
            print 'IP ' + str(address) + ' is untrusted.  Please add to TRUSTEDIPS: in option file ' + str(optionfile)
            connection.sendall('-1')
            connection.shutdown(1)
            connection.close()
            continue


    if len(rxbuffer) > 900 or 'recon' not in rxbuffer:  ##Port safety check.  Any communication must be related to recon and small.
        print 'Malformed connection from ' + str(address) + '.  Disconnecting...'
        if not DEBUG:
            connection.sendall('-1')
            connection.shutdown(1)
            connection.close()
            continue
    
    try:
        PFILENAME, options = packet_to_pfile(rxbuffer)   #TRANSLATE RECEIVE BUFFER FROM CLIENT INTO PFILE NAME
    except:
        varargs = str_to_args(rxbuffer)
        PFILENAME = str_to_args(rxbuffer)[-1]
        print 'Invalid pfile'
    
    port = SSHPORT  #UNUSED
    filename = MRRAW + PFILENAME   #full pfilename, path
            
    # COPY PFILE TO SERVER
    print 'Copying ' + filename + ' to server for recon'
    if 0 != os.system( 'sshpass '+ '-p "' + PASSWORD + '" scp -r '  + USERNAME + '@' + HOSTNAME + ':' + filename + ' ' + RECON_FILEPATH ):
        print 'Error in transfer!'
            




    # RECONSTRUCT PFILE
    print 'Reconstructing ' + PFILENAME + ' with ' + RECONSCRIPT    
    if ('--pyscript') in rxbuffer:  ## SEND A --pyscript in the CONNECITON TO RECON WITH PYSCRIPT INSTEAD
        print 'Python script!'
        pyscript = rxbuffer.split("--pyscript', '")[1].split("'")[0]
        try:
            pyscripts[pyscript](rxbuffer)
        except:
            print pyscript, ' does not run'
    else:  ##MATLAB SCRIPT
        VARGIN = str(PFILENAME[1:-2])
        if 0 != os.system('matlab -nodisplay -nojvm -nosplash -nodesktop -r "run ' + RECONSCRIPT + '('  + VARGIN +')'  + '"'):  ### quit or exit must be last matlab command!
            print 'Error in recon!'



    # COPY DICOMs to SCANNER    
    print 'Copying reconstructed dicom files to scanner'
    if 0 != os.system( 'sshpass '+ '-p "' + PASSWORD + '" scp -r '  + USERNAME + '@' + HOSTNAME + ':' + RECON_DICOM_DIR + '*' + ' ' + SCANNER_DICOM_DIR ):
        print 'Error in dicoms!'  ##WARNING!  THIS DOES NOT CATCH ALL ERRORS!


    # SEND COMPLETE MESSAGE    
    connection.sendall('Finished '+ PFILENAME)            
    connection.shutdown(1)
    connection.close()
    print 'Completed'


## CLOSE AND CLEAN UP
server.shutdown(1)
server.close()


