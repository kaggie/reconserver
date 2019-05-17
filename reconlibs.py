# -*- coding: utf-8 -*-
"""
Created on Sat Mar 18 12:36:24 2017

@author: Josh Kaggie
"""

import socket


### TRY READING AN OPTION FILE.  WRITE DEFAULT OPTIONS IF FILE DOES NOT EXIST
def readoptions(optionfile):
    try:
        optionf = open(optionfile,'r')
        HOSTNAME = optionf.readline().strip()    #recon ip address
        SIGPORT = int(optionf.readline().strip())  #recon port
        USERNAME = optionf.readline().strip()     #scanner username
        PASSWORD = optionf.readline().strip()     #scanner password
        SSHPORT = int(optionf.readline().strip())   # ssh port
        MRRAW = optionf.readline().strip()         #mrraw directory
        RECON_FILEPATH = optionf.readline().strip()     #temp directory for recon pfile on recon server
        RECONSCRIPT = optionf.readline().strip()   #script name to run recon
        RECON_DICOM_DIR = optionf.readline().strip()   #recon dicom directory
        SCANNER_DICOM_DIR = optionf.readline().strip()  #scanner dicom directory
        LOGFILE = optionf.readline().strip()     #name of file to log problems
        opts = optionf.readlines()    #reserverd
    except:
        print('Does ' + optionfile + ' exist?')
        optionf = open(optionfile,'w')
        HOSTNAME = '195.107.14.11'   #server IP address
        SIGPORT = 5902          #server port
        USERNAME = 'sdc'
        PASSWORD = 'adw2.0'       
        SSHPORT = 22      #UNUSED
        MRRAW = '/usr/g/mrraw/'    #/usr/g/mrraw/
        RECON_FILEPATH = '/tmp/recon/'   #
        RECONSCRIPT = 'reconscript'
        RECON_DICOM_DIR  = '/tmp/recon/dicoms/'
        SCANNER_DICOM_DIR = '/tmp/dicoms/'
        LOGFILE = '/tmp/reconlog'
        opts = [] # saved space    
        optionf.write(HOSTNAME+'\n'+\
                         str(SIGPORT)+'\n'+\
                         USERNAME+'\n'+\
                         PASSWORD+'\n'+\
                         str(SSHPORT)+'\n' + \
                         MRRAW+'\n' + \
                         RECON_FILEPATH+'\n' +   \
                         RECONSCRIPT + '\n' +  \
                         RECON_DICOM_DIR + '\n'  + \
                         SCANNER_DICOM_DIR + '\n' +  \
                         LOGFILE + '\n' +  \
                         '#TRUSTEDIPS:\n'
                         )                
    try:
        optionf.close()                
    except:
        print 'Cannot read or write recon.opts!'    
    
    return HOSTNAME, SIGPORT, USERNAME, PASSWORD, SSHPORT, MRRAW, RECON_FILEPATH, RECONSCRIPT, RECON_DICOM_DIR, SCANNER_DICOM_DIR, LOGFILE, opts        



def capture_packet(server):
    rxbuffer = None
    while rxbuffer == None:
        #server.settimeout(1e9)    
        server.listen(1)            
        connection, address = server.accept()    
        while True:
            rxbuffer = connection.recv(1024)
            print rxbuffer            
            if rxbuffer != None: break #return rxbuffer, connection, address
        if rxbuffer != None:
            break
            #return rxbuffer, connection, address    #EXIT LOOP WHEN DATA HAS BEEN RECEIVED                
    return rxbuffer, connection, address


def capture_packet_client(client):
    rxbuffer = None
    while rxbuffer == None:
        #server.settimeout(1e9)    
        while True:
            rxbuffer = client.recv(1024)
            print rxbuffer            
            if rxbuffer != None: break #return rxbuffer, connection, address
        if rxbuffer != None:
            break
            #return rxbuffer, connection, address    #EXIT LOOP WHEN DATA HAS BEEN RECEIVED                
    return rxbuffer

    

def packet_to_pfile(rxbuffer):
    sendvals = rxbuffer.split('[')[1].split(',')
    PFILENUM = sendvals[1].replace("'","")  ### CHANGE 1 to accurate array element
    PFILENAME = 'P' + str(int(PFILENUM)) + '.7'
    options = sendvals
    return PFILENAME, options


def args_to_str(*argv):
    argstr = ''
    for element in argv:    
        argstr = str(element) + ' '
    return argstr
    

def str_to_args(string):
    args = string.replace("'","").split('[')[1].split(']')[0].split(',')
    argout = []
    for arg in args:
        argout.append(arg.strip())
    return argout
    
def get_opts_tagvals(opts,tag):
    return opts[0].split(tag)[1].split('\n')[0].strip().split(',')
    
    
    
def pyscript1(*kwargs,**kwords):
    print 'Python script 1'
    print kwargs, kwords
    
def pyscript2(*kwargs, **kwords):
    print 'Python script 2'
    print kwargs, kwords    
    
    
pyscripts = {
        '1':pyscript1,
        '2':pyscript2
        }

    
