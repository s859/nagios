# nagios
Nagios script repository

check_all_disks.py

>Why is this needed?

Because adding a separate Nagios service monitor for every drive/filesystem on every server is tedious, and added drives and filesystems aren’t auto-discovered. This method discovers new drives and filesystems instantly. It doesn’t track utilization history in Nagios XI. If you have a critical drive or filesystem, you can still use the regular disk space checks. It can support any system that has NCPA 2.4 installed, Windows, Linux, AIX, etc.

Key dependency: NCPA at least version 2.1 on a monitored host.

Tested with NCPA 2.1 to 2.4 on AIX, Windows, Centos, SUSE Linux

Runs on Nagios 4.x and Nagios XI 5.8

$ **/usr/local/nagios/libexec/check_all_disks.py -h**  
Usage: check_all_disks.py [options]  

Options:  
  -h, --help            show this help message and exit  <br><br>
  -H HOSTNAME, --hostname=HOSTNAME  
                       The hostname to be connected to.  <br><br>
  -P PORT, --port=PORT  Port to use to connect to the client.  
  -w WARNING, --warning=WARNING  
                       Warning value to be passed for the check.  <br><br>
  -c CRITICAL, --critical=CRITICAL  
                       Critical value to be passed for the check.  <br><br>
  -t TOKEN, --token=TOKEN  
                        The token for connecting.  <br><br>
  -a ARGUMENTS, --arguments=ARGUMENTS  
                        Arguments for the plugin to be run. Not necessary  
                        unless you're running a custom plugin. Given in the  
                        same as you would call from the command line.  <br><br> 
  -T TIMEOUT, --timeout=TIMEOUT  
                        Enforced timeout, will terminate plugins after this  
                        amount of seconds. [60]  <br><br>
  -v, --verbose         Print more verbose error messages.  <br><br>
  -x EXCLUDE, --exclude=EXCLUDE  
                        Comma separated list of drives to exclude from the  
                        check. Use separator | instead of \ or /. Example -x  
                        'T:|,E:|' to exclude Windows drives T:\ and E:\  
                        Example -x '|mkcd|cd_images' to exclude Unix  
                        /mkcd/cd_images  <br><br>
  -D, --debug           Print LOTS of error messages. Used mostly for  
                        debugging.  <br><br>
  -V, --version         Print version number of plugin.  <br><br>
  -s, --secure          Require successful certificate verification. Does not  
                        work on Python < 2.7.9.  <br><br>

Please see Nagios Check_all_disks.pdf
