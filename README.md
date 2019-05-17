# reconserver
My server for handling reconstruction

This is made for GE pfiles.  Some modifications are possible so that it could work with other scanner systems.  It's fairly general and simple.  Although Gadgetron exists, this is a bit more straightforward and has inherent encryption and simple data fidelity check against hacking. It requires an ssh connection to be available.  It's also my code, so I know how to fix the problems.


# Intro
There are four files required for this:

reconlibs -- the standard library for my internet protocol
recon_signal -- The server signal that starts the recon.  This happens when a scanning sequence is done.
recon_listener -- This constantly runs on a server.  This can handle reconstruction from any server.
recon.opts -- The option file, which has on each line the

    HOSTNAME
    SIGPORT
    USERNAME
    PASSWORD
    SSHPORT
    MRRAW
    RECON_FILEPATH
    RECONSCRIPT
    RECON_DICOM_DIR
    SCANNER_DICOM_DIR
    LOGFILE


So, as an example the options file might be

    192.168.1.101
    8000
    kaggie
    mypassword
    22
    /usr/g/mrraw  #path to the GE Pfile
    /scratch/recon
    recon_my_data.m  #comments are allow
    /scratch/recon/savedatahere
    /usr/g/dicomimportpath
    log.txt



It works pretty well, although there may not be python 2 and 3 differences that I haven't accounted for.  GE MRI systems do not have Python 3 as of yet, so this will work better for Python 2.  Hopefully by having it online, it will give me an easier place to update.


I will add more later.  I'm putting various of my code online.  As for the license?  I can't be bother to figure the licenses out.  Would I really know or do anything about it if you used it?  I'd probably just be pleased.



I developed this while receiving some grant support from GlaxoSmithKline and the NIHR Cambridge Biomedical Research Council.  Now I receive some funding from EU Horizon 2020, and I will probably keep developing minor things to prevent too much code rot.






