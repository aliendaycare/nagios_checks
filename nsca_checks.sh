#!/bin/bash
#
# !!! NOTICE !!!
# This script may be overwritten at any given time!
# Please do not make any changes here, the master script is on dheid-p3430 in /home/sysadmin
# Use the distnsca script in /home/dheid as user "dheid"
# !!!!!!!!!!!!!!
#
# Version 4.5.2
#
# Revision history
#
# 4.5.2 - ADDED check_datalink check for all physical Solaris hosts
# 4.5.1 - UPDATED MySQL/MariaDB check with better syntax
# 4.5.0 - UPDATED MySQL/MariaDB check with complete re-write of check logic
# 4.4.3 - ADDED check of diskinfo for arbitrary filesystems normally excluded that should be checked
# 4.4.2 - UPDATED output of BACKUP check when no avagent running in global zone
# 4.4.1 - UPDATED MySQL check to just check mysqld process if service is enabled. TCP test causes too many probs for DBAs
# 4.4.0 - UPDATED MySQL check to use simple TCP check on port 3306
# 4.3.11 - UPDATED timeserver in NTP section from tempus.lc.ca.gov to VIP 10.10.0.55
# 4.3.10 - UPDATED check script to use temp new_nsca_service_data and replace old when finished
# 4.3.9 - UPDATED ntp check to set code to return code since check_ntp_time does not format critical output properly
# 4.3.8 - ADDED python3 binary check for calling check_cpu.py
# 4.3.7 - UPDATED df filter from '^/[a-zA-Z0-9]+|/tmp|/$|^[-_a-zA-Z0-9:]+/' to '% +/' since missing solaris filesystem /rpool
# 4.3.6 - UPDATED SEND_NSCA_BIN variable for Linux hosts from /usr/sbin to /home/sysadmin/send_nsca
# 4.3.5 - UPDATED leave /tmp/nsca_service_data for splunk systems to retrieve even if firewalled
# 4.3.4 - UPDATED df kill command to execute silently
# 4.3.3 - UPDATED logic for checking if another nsca_check.sh script is already running
# 4.3.2 - ADDED entry to delete check_prtdiag script if this script is executed in a non-global zone
# 4.3.1 - ADDED simple command to Linux hosts to remove group-write permission for Nagios homedir
# 4.3.0 - REMOVED All traces of Tivoli check and reverted to single process check result
# 4.2.3 - UPDATED Backup client to check for avamar process on solaris zones if installed.
# 4.2.2 - UPDATED Backup client section to use hostname.dat BACKUP value for low-threshold too
# 4.2.1 - UPDATED Tivoli and Avamar checks and consolidated into one monolithic check
# 4.2.0 - ADDED Avamar backup process check
# 4.1.0 - ADDED MySQL database process check
# 4.0.10 - UPDATED list of found FS in df_output to remove dupes and headers
# 4.0.9 - UPDATED Tivoli check to refer to HOSTDAT file for max allowed dsmc(ad) procs
# 4.0.8 - UPDATED Tivoli check to look for dsmc OR dsmcad process for successful check
# 4.0.7 - ADDED support for checking of exceptional filesystems in disk_info.dat
# 4.0.6 - UPDATED Tivoli check to only show global procs on global host
# 4.0.6 - UPDATED Multipath logic to check hostname.dat file for correct number of paths
# 4.0.5 - REMOVED diskinfo variable from list of unset arguments in zpool section
# 4.0.4 - REMOVED LDCMON1z and 2Z from monitor server lists
# 4.0.3 - UPDATED command to list all drupal sites into /tmp/sites.local
# 4.0.2 - UPDATED SMF check to ensure Solaris version 10 or greater
# 4.0.1 - ADDED new monitoring server LDCMONPRD to monitor host list
# 4.0.0 - ADDED support for Apple systems (Darwin)
# 3.4.3 - ADDED new monitoring server LDCMONTST to monitor host list
# 3.4.2 - REMOVED line which removed extra monitor host file in prep of new monitor host
# 3.4.1 - UPDATED multipaths section to look for value in HOSTDAT
# 3.4.0 - ADDED command to check multipath status if present
# 3.3.9 - UPDATED the df grep to catch hyphenated zfs mounts
# 3.3.8 - UPDATED egrep patterns for filesystems again
# 3.3.7 - UPDATED additional tweaks to the df call to only look for specific FS types
# 3.3.6 - UPDATED NTP section to call check_ntp_time with -q argument
# 3.3.5 - UPDATED the df grep to catch the /netxxx/ filesystems on lcimpdev1
# 3.3.4 - UPDATED NTP section to use check_ntp_time rather than obsolete check_ntp
# 3.3.3 - ADDED command to list all drupal sites into /tmp/sites.local for server pickup
# 3.3.2 - ADDED check for directive in dat file for post-processing of service data file
# 3.3.1 - FIXED tivoli check to execute when ZONE is null
# 3.3.0 - ADDED support for Ubuntu operating systems
# 3.2.3 - UPDATED tivoli check to NOT exclude < 5.10 Solaris systems
# 3.2.2 - ADDED nsca client conf file permission lockdown (600)
# 3.2.1 - FIXED call to arch for Linux hosts
# 3.2.0 - ADDED new checks: tivoli client process and check_solaris_smf
# 3.1.2 - FIXED df error output now goes to /dev/null
# 3.1.1 - FIXED check_cpu status setting and unset code after all checks
# 3.1.0 - ADDED check_cpu check
# 3.0.15 - ADDED further Linux i686 or x86_64 branches to env setup
# 3.0.14 - UDPATED df grep to include more filesystems and mask /platform/sun, libc.so, etc.
# 3.0.13 - FIXED check_prtdiag invocation to discard errors
# 3.0.12 - CHANGED check_disk logic to use pgrep/pkill instead of grep/kill - Thanks, Steve!
# 3.0.11 - FIXED nslookup paths for specific host OS
# 3.0.10 - ADDED check for DNS services prior to sending passive data
# 3.0.9 - FIXED explicit call to ntpdate in /usr/sbin
# 3.0.8 - ADDED -r option check_load
# 3.0.7 - ADDED handling of local config setting for NTP server
# 3.0.6 - FIXED handling of XTRA checks that do not return proper status name
# 3.0.5 - FIXED if statements on 468 and 485 by quoting variables
# 3.0.4 - FIXED query of hostname to convert to lowercase
# 3.0.3 - CHANGED ldcmon2z to only send service data to ldcmon1z, and vice-versa
# 3.0.2 - ADDED special handling for firewalled hosts
# 3.0.1 - ADDED checks for linux volume group filesystems and raids
# 3.0.0 - ADDED support for redhat hosts
# 2.9.9 - Change shebang to /bin/bash and see if any hosts break
# 2.4.5 - ADDED check of zpool status and capacity
# 2.4.4 - UPDATED INODE threshold check to look for filesystem custom threshold in inode_info.dat
#         UPDATED output line for XTRA commands to output only executable name without arguments
# 2.4.3 - ADDED check of host dat file for custom memory thresholds
# 2.4.2 - UPDATED every output line to nagios to include the proper check command for PNP4Nagios
# 2.4.1 - ADDED new check for free system memory accounting for ZFS ARC
# 2.4 - ADDED ability to /usr/sbin/install new checks via this script
# 2.3.12 - UPDATED mask to df check for oracle ZFS filesystems
# 2.3.11 - ADDED mask to df check for ZFS filesystems
# 2.3.10 - ADDED INODE threshold to disk check
#        - REMOVED aisgw from monitoring host list
# 2.3.9 - FIXED some comments in this script and activated the removal of extra monitor hosts file
# 2.3.8 - CHANGED ldcais to ldcmon2z in the monitoring hosts list
# 2.3.7 - CHANGED aislab1 to aisgw in the monitoring hosts list
# 2.3.6 - ADDED aislab1 back to the monitoring hosts list
# 2.3.5 - ADDED ability to check local services via XTRA statements in the hostname.dat file
#       - REMOVED the rm statement which deleted monitor.hosts in preparation for next wave
# 2.3.4 - Since aislab1 is down, change to ldcmon1z and remove any monitor.hosts
# 2.3.3 - Remove /mnt from list of filesystems to check
# 2.3.2 - ADDED check to see if monitor host 2 is alive before trying to send nsca data
# 2.3.1 - ADDED custom section for load and overwrite notice at the top
# 2.3 - ADDED search for monitor.hosts. Now nsca data will send to any hosts in the file.
#     - ADDED echo statements to show which monitor hosts receive nsca data.
#     - ADDED revision history :)
#     - UPDATED df command to use the '-l' option, maybe bypassing net failues.
# 2.2 - ADDED secondary MONITOR_HOST2 variable due to the inception of Groundwork.
#     - FIXED bug in df output section
#<2.2 - I forget. Too many changes.
#

# This script runs checks against local services and resources, aggregates them into a data
# file, and sends them to the ldcmonprd/tst nsca daemons for processing into Nagios
# See http://ldcmon.lc.ca.gov/nagios for details

# Determine if host OS is Apple, Solaris or Linux
HOSTOS=`uname -s`
HOSTVER=`uname -r`

if [ "$HOSTOS" = "SunOS" ]; then
	export SCRIPT_DIR=/opt/csw/libexec/nagios-plugins
	export OS_DIR=/export/home/operator/bin
	export INSTALL_BIN=/usr/sbin/install 
	export ECHO_BIN=/usr/bin/echo
	export HOSTNAME=`hostname |tr A-Z a-z`
	export SEND_NSCA_BIN=/opt/csw/bin/send_nsca
	export SEND_NSCA_CFG=/opt/csw/etc/send_nsca.cfg
	export PING_BIN='/usr/sbin/ping'
	export NSLOOKUP_BIN='/usr/sbin/nslookup'
	export HOSTARCH=`/usr/bin/arch`
	export OS_REV=`/usr/bin/uname -r`
	export MULTIPATH_CMD='/usr/sbin/mpathadm'
	if [ -x /usr/bin/zonename ]; then export ZONE=`/usr/bin/zonename` ; fi
	# Delete check_prtdiag if this is not a global zone
	if [ "$ZONE" != "global" -a "x$ZONE" != "x" ] ; then rm $SCRIPT_DIR/check_prtdiag 2>/dev/null ; fi
	export PYTHON_BIN=''
elif [ "$HOSTOS" = "Linux" ]; then
	export PATH="$PATH:/usr/sbin:/sbin:/usr/libexec"
	if [ -r /usr/lib64/nagios/plugins/negate ]; then
		export SCRIPT_DIR='/usr/lib64/nagios/plugins'
	else
		export SCRIPT_DIR='/usr/lib/nagios/plugins'
	fi
	export OS_DIR=/home/sysadmin
	export INSTALL_BIN=/usr/bin/install 
	export ECHO_BIN='/bin/echo -e'
	export CHKCONFIG_BIN=`which chkconfig 2>/dev/null || echo "/usr/bin/systemctl is-enabled"`
	[ -x /usr/bin/systemctl ] && CHKCONFIG_BIN="/usr/bin/systemctl is-enabled"
	export HOSTNAME=`hostname -s |tr A-Z a-z`
	export SEND_NSCA_BIN=/home/sysadmin/send_nsca
	HOSTDIST=`uname -a |grep -io 'ubuntu'`
	if [ "$HOSTDIST" = "Ubuntu" ]; then
		export SEND_NSCA_CFG=/etc/send_nsca.cfg
	else
		export SEND_NSCA_CFG=/etc/nagios/send_nsca.cfg
	fi
	export PING_BIN='/bin/ping -c 1 -w 1 -q'
	export NSLOOKUP_BIN='/usr/bin/nslookup'
	export HOSTARCH='/bin/arch'
	export MULTIPATH_CMD='/sbin/multipath'
	if [ ! -f '/etc/multipath.conf' ]; then MULTIPATH_CMD=''; fi
	chmod g-w ~nagios 2>/dev/null #Allows passwordless SSH by Nagios user on ldcmonprd/tst
	if [ -x /usr/bin/python3 ]; then export PYTHON_BIN='/usr/bin/python3' ; else export PYTHON_BIN='/usr/bin/python' ; fi
	chown root:users $OS_DIR/nsca_checks.sh && chmod 764 $OS_DIR/nsca_checks.sh
elif [ "$HOSTOS" = "Darwin" ]; then
	export SCRIPT_DIR='/opt/local/libexec/nagios/'
	export OS_DIR='/Users/sysadmin'
	export INSTALL_BIN='/usr/bin/install'
	export ECHO_BIN='/opt/local/bin/gecho -e'
	export HOSTNAME=`hostname -s |tr A-Z a-z`
	export SEND_NSCA_BIN='/opt/local/sbin/send_nsca'
	export SEND_NSCA_CFG='/opt/local/etc/nsca/send_nsca.cfg'
	export PING_BIN='/sbin/ping -o -t1 -q'
	export NSLOOKUP_BIN='/usr/bin/nslookup'
	export HOSTARCH='/usr/bin/arch'
	export MULTIPATH_CMD=''
	export PYTHON_BIN=''
else
	echo "Unable to determine host OS!"
	exit -1
fi

export HOSTDAT="$OS_DIR/$HOSTNAME.dat"
export MONITOR_HOST='ldcmonprd.calegis.net'
export MONITOR_HOST2='ldcmontst.calegis.net'
export MONITOR_HOST3=''
export APPROVAL_FILE='/tmp/approved_checks'

# Have to make sure we are not already running
# This causes problems when NFS mounts die and it causes the disk check to hang
#  which causes these checks to pile up which leads to other problems.
# I tried doing this with PIDs but it gets way too complicated. Flag files FTW!
if [ -a /tmp/nsca_checks_running ]; then
	# What if the system rebooted during a check? Let us check the PID...
	if [ "`pgrep nsca_checks.sh |xargs|grep $(cat /tmp/nsca_checks_running)`"  ] ; then
		echo "Another nsca_checks.sh script is running, please look for process `cat /tmp/nsca_checks_running`"
		exit 1
	fi
fi
# If we get here, there is no flag file, or the flag file is from an interrupted instance
echo "$$" > /tmp/nsca_checks_running ; rm -f /tmp/new_nsca_service_data 2>/dev/null ; touch /tmp/new_nsca_service_data 2>/dev/null

# Check for new check_ files in tmp and look for approval file
# We cannot simply copy over every file beginning with check_* into our plugins directory
# So we must also list the files to be installed in a seperate approval file which lists
# the files to be installed. We are using the /usr/sbin/install utility to place them.

# First discover new check_ scripts
num=`ls /tmp/check_* 2>/dev/null |wc -l|tr -d ' '`
if [ $num -gt 0 ]; then # There be new checks here, Captain!
	# Now we should check for the presence of the approval file "approved_checks"
	if [ -s $APPROVAL_FILE ]; then
		# Now walk through the approval file installing each new check_ script
		for file in `cat $APPROVAL_FILE`; do
			# Is the check_ script specified in the approval file present?
			if [ -x "$file" ]; then
				# Install the file with perms 755, owner root, making a backup, and do it quietly
				echo "Installing $file in $SCRIPT_DIR..."
				if [ "$HOSTOS" = "SunOS" ]; then
					$INSTALL_BIN -f $SCRIPT_DIR -u root -o -s $file
				elif [ "$HOSTOS" = "Linux" ]; then
					$INSTALL_BIN -t $SCRIPT_DIR -o root -b $file >/dev/null
				fi

				if [ $? -ne 0 ]; then # Crap!
					echo "ERROR while attempting to install $file on host `hostname`!"
					exit 1
				fi
			else echo "Approval file found containing entry for $file, but $file not present for install"
			fi
		done
		# If we got here, then we are done installing the new check_ scripts and should remove the approval file
		rm $APPROVAL_FILE
	fi
fi
unset num

# 3.2.2 Lock down the permissions on nsca client conf file
chmod 600 $SEND_NSCA_CFG 2>/dev/null

# ZPool Checks
#DEBUG#echo 'ZPool checks...' >/tmp/nsca_checks.debug #DEBUG#
diskinfo=$OS_DIR/disk_info.dat

if [ -x /usr/sbin/zpool -a -x $SCRIPT_DIR/check_zpool ]; then

	for pool in `/usr/sbin/zpool list -Ho name |xargs`
	do
		w=90
		c=95
        	if [ -s $diskinfo ]; then
                	egrep "^$pool " $diskinfo >/dev/null
                	if [ $? -eq 0 ]; then
                        	w=`egrep "^$pool " $diskinfo |cut -d ' ' -f2`
                        	c=$( expr $w + 5 )
                        	if [ $c -gt 99 ]; then c=99; fi
                	fi
        	fi
        	output=`$SCRIPT_DIR/check_zpool -w $w -c $c $pool`
        	status=`echo $output |awk '{print $2}'`
        	case $status in
        	OK)
                	code=0
                	;;
        	WARNING)
                	code=1
                	;;
        	CRITICAL)
                	code=2
                	;;
        	UNKNOWN)
                	code=3
                	;;
        	esac

        	$ECHO_BIN "$HOSTNAME\t$pool zpool\t$code\t$output [check_zpool]" >>/tmp/new_nsca_service_data
		unset code output status
	done
	#DEBUG#echo Done >>/tmp/nsca_checks.debug #DEBUG#
fi
		
# Disk Checks
#DEBUG#echo 'Disk checks...' >/tmp/nsca_checks.debug #DEBUG#

diskinfo=$OS_DIR/disk_info.dat
inodeinfo=$OS_DIR/inode_info.dat

# In order to avoid problems with df not exiting properly when nfs mounts time out, rather than running df directly, we will start it in a seperate process, capture whatever output we can get, then kill the process after 2 seconds.

# Leave the last one # rm /tmp/df_output 2>/dev/null
unset thispid ; thispid=$$
if [ $HOSTOS = 'SunOS' ]; then
	> /tmp/df_output.new
	df -lkF ufs >> /tmp/df_output.new 2>/dev/null &
	df -lkF zfs >> /tmp/df_output.new 2>/dev/null &
	df -lk /tmp >> /tmp/df_output.new 2>/dev/null &
	df -lkF pcfs >> /tmp/df_output.new 2>/dev/null &
	if [ -s $diskinfo ]; then
		for fs in `cat $diskinfo |awk '{print $1}'`; do
			df -k $fs >> /tmp/df_output.new 2>/dev/null &
		done
	fi
elif [ $HOSTOS = 'Linux' ]; then
	> /tmp/df_output.new
	# args for local, human-readable, POSIX formated, excluding certain filesystem types
	df -lhPx tmpfs -x overlay >> /tmp/df_output.new 2>/dev/null &
	if [ -s $diskinfo ]; then
		for fs in `cat $diskinfo |awk '{print $1}'`; do
			df -hP $fs >> /tmp/df_output.new 2>/dev/null &
		done
	fi
elif [ $HOSTOS = 'Darwin' ]; then
	> /tmp/df_output.new
	df -PhT hfs |tr ' ' _ |sed 's/__/ /g'>> /tmp/df_output.new 2>/dev/null &
fi
# Wait 2 seconds...
sleep 2
unset dfpid ; dfpid=`pgrep -U root -P $thispid df`
if [ -n "$dfpid" ]; then
	echo "df still running: $dfpid" >>/tmp/df_output
	pkill -U root -P $thispid df 2>/dev/null
fi
if [ -s /tmp/df_output.new ]; then mv /tmp/df_output.new /tmp/df_output; fi

for fs in `cat /tmp/df_output |sort -u |egrep '% +/' |egrep -iv '/platform/sun|/libc.so|/vob/|/cdrom/|/dev/loop|/net/|/dev$|/devices$|/mnt$' |awk '{print $6}' |sort -u |xargs`
do
	# This is ugly, but necessary
	if [ "$HOSTOS" = "Darwin" ]; then
		fs=`echo $fs|sed 's/_/ /g'`
	fi
	w=10
	c=5
        if [ -s $diskinfo ]; then
                grep "$fs " $diskinfo >/dev/null
                if [ $? -eq 0 ]; then
                        w=$( expr 99 - `egrep "$fs " $diskinfo |cut -d ' ' -f2` )
                        c=$( expr $w - 5 )
                        if [ $c -lt 1 ]; then c=1; fi
                fi
        fi
	W=$w
	K=$c
        if [ -s $inodeinfo ]; then
                grep "$fs " $inodeinfo >/dev/null
                if [ $? -eq 0 ]; then
                        W=$( expr 99 - `egrep "$fs " $inodeinfo |cut -d ' ' -f2` )
                        K=$( expr $W - 5 )
                        if [ $K -lt 1 ]; then K=1; fi
                fi
        fi
        output=`$SCRIPT_DIR/check_disk -w ${w}% -c ${c}% -W ${W}% -K ${K}% "$fs"`
        status=`echo $output |awk '{print $2}'`
        case $status in
        OK)
                code=0
                ;;
        WARNING)
                code=1
                ;;
        CRITICAL)
                code=2
                ;;
        UNKNOWN)
                code=3
                ;;
        esac

        $ECHO_BIN "$HOSTNAME\t$fs Partition\t$code\t$output [check_disk]" >>/tmp/new_nsca_service_data
	unset code output status
done
#DEBUG#echo Done >>/tmp/nsca_checks.debug #DEBUG#

# Current Load
#DEBUG#echo 'Current Load...' >>/tmp/nsca_checks.debug #DEBUG#
w='5.0,4.0,3.0 ' # 1, 5, and 10 minute averages
c='10.0,6.0,4.0'

if [ -s $HOSTDAT ]; then
	LOAD=`egrep '^LOAD ' $HOSTDAT|cut -d ' ' -f2`
	if [ -n "$LOAD" ] ;then
		w=`echo $LOAD |cut -d '|' -f1`
		c=`echo $LOAD |cut -d '|' -f2`
	fi
fi

output=`$SCRIPT_DIR/check_load -r -w $w -c $c`
status=`echo $output |cut -d ' ' -f1`
case $status in
OK)
	code=0
	;;
WARNING)
	code=1
	;;
CRITICAL)
	code=2
	;;
UNKNOWN)
	code=3
	;;
esac
$ECHO_BIN "$HOSTNAME\tCurrent Load\t$code\t$output [check_load]" >>/tmp/new_nsca_service_data
#DEBUG#echo Done >>/tmp/nsca_checks.debug #DEBUG#
unset code output status

# Solstice Disksuite / Metadisk / Linux Raid check
#DEBUG#echo 'Metadisk Checks...' >>/tmp/nsca_checks.debug #DEBUG#
cat /tmp/df_output |egrep '^/dev/md' >/dev/null
return=$?
if [ $return -eq 0 ]; then
	if [ -x $SCRIPT_DIR/check_svm -o -x $SCRIPT_DIR/check_linux_raid ]; then
		egrep '^SVM ' $HOSTDAT >/dev/null 2>&1
		if [ $? -lt 1 ]; then SVM=`egrep '^SVM ' $HOSTDAT|cut -d ' ' -f2`
		else SVM=2
		fi
		if [ $HOSTOS = 'SunOS' ]; then
			output=`$SCRIPT_DIR/check_svm -mbc$SVM`
			status=`echo $output |cut -d ':' -f1`
		elif [ $HOSTOS = 'Linux' ]; then
        		output=`$SCRIPT_DIR/check_linux_raid`
        		status=`echo $output |awk '{print $1}'`
		fi
		case $status in
		OK)
                	code=0
                	;;
        	WARNING)
                	code=1
                	;;
        	CRITICAL)
                	code=2
                	;;
        	UNKNOWN)
                	code=3
                	;;
        	esac
		$ECHO_BIN "$HOSTNAME\tMetadisk\t$code\t$output" >>/tmp/new_nsca_service_data
		#DEBUG#echo Done >>/tmp/nsca_checks.debug #DEBUG#
		unset code output status
	fi
fi
unset return

# Hardware checks
#DEBUG#echo 'Hardware Checks...' >>/tmp/nsca_checks.debug #DEBUG#
if [ -x $SCRIPT_DIR/check_prtdiag  -a -x /usr/sbin/prtdiag ]; then
	cd $SCRIPT_DIR
	output=`./check_prtdiag 2>/dev/null`
	cd - >/dev/null
	status=`echo $output |cut -d ' ' -f1`
	case $status in
	OK)
		code=0
		;;
	WARNING)
		code=1
		;;
	CRITICAL)
		code=2
		;;
	UNKNOWN)
		code=3
		;;
	esac
	$ECHO_BIN "$HOSTNAME\tHardware Check\t$code\t$output" >>/tmp/new_nsca_service_data
	#DEBUG#echo Done >>/tmp/nsca_checks.debug #DEBUG#
	unset code output status
fi

# NTP check
#DEBUG#echo 'NTP Check...' >>/tmp/nsca_checks.debug #DEBUG#
timeserver=10.10.0.55
if [ -r /etc/ntp.conf ]; then
	for timeserver in `cat /etc/ntp.conf |grep '^server' |cut -d ' ' -f2`; do
		/usr/sbin/ntpdate -q $timeserver >/dev/null 2>&1
		if [ $? -lt 1 ]; then break ; fi
	done
fi

w='30' # 30 seconds
c='60' # 60 seconds

if [ -s $HOSTDAT ]; then
	NTP=`egrep '^NTP ' $HOSTDAT|cut -d ' ' -f2`
	if [ -n "$NTP" ] ;then
		w=`echo $NTP |cut -d '|' -f1`
		c=`echo $NTP |cut -d '|' -f2`
	fi
fi

output=`$SCRIPT_DIR/check_ntp_time -H $timeserver -w${w} -c${c} -q`
code=$?
status=`echo $output|awk '{print $2}' |tr -d :`
case $status in
OK)
	code=0
	;;
WARNING)
	code=1
	;;
CRITICAL)
	code=2
	;;
UNKNOWN)
	code=3
	;;
esac
$ECHO_BIN "$HOSTNAME\tNTP\t$code\t$output [check_ntp]" >>/tmp/new_nsca_service_data
#DEBUG#echo Done >>/tmp/nsca_checks.debug #DEBUG#
unset code output status w c j k LOAD

# CPU check
#DEBUG# echo 'CPU Check...' >>/tmp/nsca_checks.debug #DEBUG#
if [ -x $SCRIPT_DIR/check_cpu.py ]; then
	w=20 # 80 percent used
	c=10  # 90 percent used

	if [ -s $HOSTDAT ]; then
		CPU=`egrep '^CPU ' $HOSTDAT|cut -d ' ' -f2`
		if [ -n "$CPU" ] ;then
			w=`echo $CPU |cut -d '|' -f1`
			c=`echo $CPU |cut -d '|' -f2`
		fi
	fi

	#DEBUG# echo "Executing: $SCRIPT_DIR/check_cpu.py -v -w$w -c$c" >> /tmp/nsca_checks.debug #DEBUG#
	output=`$PYTHON_BIN $SCRIPT_DIR/check_cpu.py -v -w$w -c$c`
	#DEBUG# echo $output >>/tmp/nsca_checks.debug #DEBUG#
	status=`echo $output|awk '{print $2}' |tr -d : `
	case $status in
	OK)
		code=0
		;;
	WARNING)
        	code=1
        	;;
	CRITICAL)
        	code=2
        	;;
	UNKNOWN)
        	code=3
        	;;
	esac
	$ECHO_BIN "$HOSTNAME\tCPU Utilization\t$code\t$output [check_cpu]" >>/tmp/new_nsca_service_data
	#DEBUG#echo Done >>/tmp/nsca_checks.debug #DEBUG#
	unset code output status w c MEM
fi

# Memory check
#DEBUG#echo 'Memory Check...' >>/tmp/nsca_checks.debug #DEBUG#
if [ -x $SCRIPT_DIR/check_mem.pl ]; then
	w=90 # 90 percent used
	c=95  # 95 percent used

	if [ -s $HOSTDAT ]; then
		MEM=`egrep '^MEM ' $HOSTDAT|cut -d ' ' -f2`
		if [ -n "$MEM" ] ;then
			w=`echo $MEM |cut -d '|' -f1`
			c=`echo $MEM |cut -d '|' -f2`
		fi
	fi

	output=`$SCRIPT_DIR/check_mem.pl -u -w $w -c $c -C`
	#DEBUG# echo "Executing: $SCRIPT_DIR/check_mem.pl -u -w $w -c $c -C" >> /tmp/nsca_checks.debug #DEBUG#
	#DEBUG# echo $output >>/tmp/nsca_checks.debug #DEBUG#
	status=`echo $output|awk '{print $2}'`
	case $status in
	OK)
		code=0
		;;
	WARNING)
        	code=1
        	;;
	CRITICAL)
        	code=2
        	;;
	UNKNOWN)
        	code=3
        	;;
	esac
	$ECHO_BIN "$HOSTNAME\tMemory\t$code\t$output [check_mem]" >>/tmp/new_nsca_service_data
	#DEBUG#echo Done >>/tmp/nsca_checks.debug #DEBUG#
	unset code output status w c MEM
fi

# Backup client check
if [ -x /opt/AVMRclnt/bin/avagent.bin -o -x /usr/local/avamar/bin/avagent.bin ]; then
        # Backup client is installed and should be running unless there is a BACKUP entry with a 0 value
        # Can there be more than one backup process?
        NUM=1
        if [ -s $HOSTDAT ]; then
                NUM=`egrep '^BACKUP' $HOSTDAT|cut -d '|' -f2`
                if [ "$NUM" == "" ] ;then NUM=1 ; fi
        fi

        # If the BACKUP value is set to 0, do not check
        if [ $NUM -ne 0 ]; then
                if [ "x$ZONE" = "xglobal" ] ;then
			# check_procs does not understand zones so we have to get fancy
                        return=`ps -feZ |grep 'global.*avagent.bin' |grep -v grep |wc -l|xargs`
                        case $return in
                                0)
					# No avagent running in global zone - CRITICAL - tweak output of check_procs to reflect
                                        pre_output=`$SCRIPT_DIR/check_procs -c 9$NUM: -C avagent.bin -u root`
					output=`echo $pre_output |sed 's/,/ in global zone,/' |sed 's/procs=[1-9]/procs=0/'|sed 's/[1-9] process/0 processes/'`
                                        code=2
                                        ;;
                                1)
					# Only 1 avagent running in global so tweak output of check_procs
                                        pre_output=`$SCRIPT_DIR/check_procs -c $NUM: -C avagent.bin -u root`
					output=`echo $pre_output |sed 's/,/ in global zone,/' |sed 's/procs=[2-9]/procs=1/'|sed 's/[2-9] processes/1 process/'`
                                        code=0
                                        ;;
                                *)
					# More that $NUM avagents running in global zone
                                        output=`$SCRIPT_DIR/check_procs -w :$NUM -C avagent.bin -u root`
                                        code=1
                                        ;;
                        esac
                else
                        output=`$SCRIPT_DIR/check_procs -c 1: -w :$NUM -C avagent.bin -u root`
                        code=$?
                fi

                $ECHO_BIN "$HOSTNAME\tBackup client\t$code\t$output [check_procs]" >>/tmp/new_nsca_service_data
                unset return code output NUM
        fi
fi

# Solaris SMF services check
if [ $HOSTOS = 'SunOS' -a `echo $HOSTVER |cut -d. -f2` -ge 10 -a -x $SCRIPT_DIR/check_solaris_smf ]; then
	output=`$SCRIPT_DIR/check_solaris_smf -w MNT -c DGD,OFF`
	status=`echo $output|awk '{print $3}'`
	case $status in
	OK)
		code=0
		;;
	WARNING)
        	code=1
        	;;
	CRITICAL)
        	code=2
        	;;
	UNKNOWN)
        	code=3
        	;;
	*)
		code=$return
		;;
	esac
	$ECHO_BIN "$HOSTNAME\tSMF services\t$code\t$output [check_solaris_smf]" >>/tmp/new_nsca_service_data
	unset code output status
fi

# Multipath status check
if [ -x "$MULTIPATH_CMD" -a -x "$SCRIPT_DIR/check_multipath_$HOSTOS" ]; then
	# Typical number of multipaths is sixteen but it varies and there is
	#  no way to tell from the system what it should have.
	# And during replacements of the fabric, the system may think there
	#  are less total paths than sixteen.
	# The total number should be placed in the HOSTDAT file.
	n=16
	if [ -s $HOSTDAT ]; then
		n=`egrep '^MULTIPATHS ' $HOSTDAT|cut -d ' ' -f2`
		if [ ! -n "$n" ] ;then
		n=16
		fi
	fi

	output=`$SCRIPT_DIR/check_multipath_$HOSTOS -n $n`
	status=`echo $output|cut -d: -f1 |awk '{print $2}'`
	case $status in
	OK)
		code=0
		;;
	WARNING)
       		code=1
       		;;
	CRITICAL)
       		code=2
       		;;
	UNKNOWN)
       		code=3
       		;;
	*)
		code=$return
		;;
	esac
	$ECHO_BIN "$HOSTNAME\tMultipath status\t$code\t$output [check_multipath]" >>/tmp/new_nsca_service_data
	unset code output status n PATHS
fi

# MySQL DB check
mysqlbin=1
[ -x /usr/libexec/mysqld -o -x /usr/libexec/mariadb ] && mysqlbin=$?
if [ -d /var/lib/mysql -a "$mysqlbin" -eq 0 ]; then
	binname=""
	mystate=`$CHKCONFIG_BIN mysqld 2>/dev/null` 
	[ $? -eq 0 -o "$mystate" == "enabled" ] && binname="mysqld"
	#DEBUG# echo "mystate=$mystate"
	[ -z "$binname" -o "$mystate" == "alias" ] && mystate=`$CHKCONFIG_BIN mariadb 2>&1` && binname="mariadbd"
	[ "$binname" == "mariadbd" -a ! -x /usr/sbin/mariadbd ] && binname="mysqld"
	#DEBUG# echo "binname=$binname"
	if [ -n "$binname" ]; then
		# MySQL should be running so now we will check it
		output=`$SCRIPT_DIR/check_procs -c1: -C $binname -u mysql`
		code=$?
		$ECHO_BIN "$HOSTNAME\tMySQL service\t$code\t$output [check_procs]" >>/tmp/new_nsca_service_data
	fi
	unset mystate code output binname
fi ; unset mysqlbin

# Datalink status check
if [ "x$ZONE" == "xglobal" -a -x $SCRIPT_DIR/check_datalinks -a -x /usr/sbin/dladm ]; then
	output=`$SCRIPT_DIR/check_datalinks`
	status=`echo $output|awk '{print $1}'`
        case $status in
        OK)
                code=0
                ;;
        WARN)
                code=1
                ;;
        CRIT)
                code=2
                ;;
        UNK)
                code=3
                ;;
        *)
                code=3
                ;;
        esac
	$ECHO_BIN "$HOSTNAME\tDatalink status\t$code\t$output [check_datalinks]" >>/tmp/new_nsca_service_data
	unset code output status
fi


# Extra checks to run locally based on entries in the hostname.dat file
grep XTRA $HOSTDAT >/dev/null 2>&1
if [ $? -eq 0 ]; then
	grep '^XTRA' $HOSTDAT |cut -d\| -f2- |while read xtra; do
		xtra_name=`echo $xtra |cut -d\| -f1`
		xtra_cmd=`echo $xtra |cut -d\| -f2`
		xtra_bin=`echo $xtra |cut -d\| -f3`
		if [ "$xtra_cmd" = "" ]; then
			code=3; output="Error in $HOSTDAT"
			$ECHO_BIN "$HOSTNAME\t$xtra_name\t$code\t$output" >>/tmp/new_nsca_service_data
			continue
		fi
		output=`$SCRIPT_DIR/$xtra_cmd`
		return=$?
		status=`echo $output |cut -d: -f1 |awk '{print $2}'`
		case $status in
		OK)
			code=0
			;;
		WARNING)
        		code=1
        		;;
		CRITICAL)
        		code=2
        		;;
		UNKNOWN)
        		code=3
        		;;
		*)
			code=$return
			;;
		esac
		if [ ! -n "$xtra_bin" ]; then xtra_bin=`echo $xtra_cmd | cut -d\  -f 1` ; fi
		$ECHO_BIN "$HOSTNAME\t$xtra_name\t$code\t$output [$xtra_bin]" >>/tmp/new_nsca_service_data
		#DEBUG# echo Done >>/tmp/nsca_checks.debug #DEBUG#
		unset code output status xtra_name xtra_cmd
	done
fi

# Database check
# Here is the command to look for Oracle DBs
# for DB in `ps -ef |egrep 'ora_pmon_[A-Z]'|awk '{print $9}'` ; do dbase=`echo $DB |cut -d_ -f3`; echo "Found $dbase"; done

# Drupal site discovery
# This section scans for Drupal sites and dumps the names into a text file for pickup
#  by the pull_firewalled_service_data.sh script
#ls -1 /var/www/html/sites 2>/dev/null |egrep 'gov$|net$' > /tmp/sites.local 2>/dev/null
# This is the approved method for generating site list
grep -h ServerName /etc/httpd/vhosts/site*.conf 2>/dev/null |awk '{print $2}' |uniq >/tmp/sites.local 2>/dev/null

# Post-processing of service data
grep POST $HOSTDAT >/dev/null 2>&1
if [ $? -eq 0 ]; then
	grep '^POST' $HOSTDAT |cut -d\| -f2- |while read post; do
		post_expect=`echo $post |cut -d\| -f1`
		post_cmd=`echo $post |cut -d\| -f2-`
		if [ "$post_cmd" = "" ]; then
			code=3; output="Error in $HOSTDAT"
			$ECHO_BIN "$HOSTNAME\tPost Processing\t$code\t$output" >>/tmp/new_nsca_service_data
			continue
		fi
		output=`eval $post_cmd`
		code=$?
		if [ $code -ne $post_expect ]; then
			$ECHO_BIN "$HOSTNAME\tPost Processing\t$code\t$output" >>/tmp/new_nsca_service_data
		fi
		#DEBUG#echo Done >>/tmp/nsca_checks.debug #DEBUG#
		unset code output post_expect post_cmd
	done
fi

# Clobber old nsca_service_data with new_nsca_service_data
mv /tmp/new_nsca_service_data /tmp/nsca_service_data

#DEBUG#cat /tmp/nsca_service_data >> /tmp/nsca_checks.debug #DEBUG#
# All checks are done, transmit now
# 3.0.2 - First check to see if this host is firewalled
grep '^FIREWALLED$' $HOSTDAT >/dev/null 2>&1
wall=$?
if [ "$wall" -eq 0 ]; then
	# This host lives behind a firewall that cannot transmit data back to the
	#  monitor hosts. Move the service data file and wrap up
	> /tmp/service_data_payload
	cp -p /tmp/nsca_service_data /tmp/service_data_payload
	rm /tmp/nsca_checks_running
	exit 0
fi ; unset wall

rm /tmp/send_nsca.out 2>/dev/null
# Check for DNS service before sending data
$NSLOOKUP_BIN -timeout=3 $MONITOR_HOST >/dev/null 2>&1
if [ $? -gt 0 ]; then
	echo "Unable to resolve $MONITOR_HOST to IP at this time" >/tmp/send_nsca.out
	rm /tmp/nsca_checks_running
	exit
fi

MHOST=`echo $MONITOR_HOST |cut -d\. -f1`
if [ "$MHOST" != "$HOSTNAME" ]; then
	$ECHO_BIN "$MONITOR_HOST: \c" >/tmp/send_nsca.out
	if [ -x /usr/local/bin/pingtcp ]; then
		/usr/local/bin/pingtcp $MONITOR_HOST 22 2>/dev/null
	else
		$PING_BIN $MONITOR_HOST >/dev/null 2>&1
	fi
	
	if [ $? -eq 0 ]; then
		$SEND_NSCA_BIN $MONITOR_HOST -c $SEND_NSCA_CFG </tmp/nsca_service_data >>/tmp/send_nsca.out
	else
		echo "Unreachable!" >>/tmp/send_nsca.out
	fi
fi ; unset MHOST

if [ -n "$MONITOR_HOST2" ]; then
	MHOST=`echo $MONITOR_HOST2 |cut -d\. -f1`
	if [ "$MHOST" != "$HOSTNAME" ]; then
		$ECHO_BIN "$MONITOR_HOST2: \c" >>/tmp/send_nsca.out
		if [ -x /usr/local/bin/pingtcp ]; then
			/usr/local/bin/pingtcp $MONITOR_HOST2 22 2>/dev/null
		else
			$PING_BIN $MONITOR_HOST2 >/dev/null 2>&1
		fi
	
		if [ $? -eq 0 ]; then
			$SEND_NSCA_BIN $MONITOR_HOST2 -c $SEND_NSCA_CFG </tmp/nsca_service_data >>/tmp/send_nsca.out
		else
			echo "Unreachable!" >>/tmp/send_nsca.out
		fi
	fi ; unset MHOST
fi

if [ -n "$MONITOR_HOST3" ]; then
	MHOST=`echo $MONITOR_HOST3 |cut -d\. -f1`
	if [ $MHOST != $HOSTNAME ]; then
		$ECHO_BIN "$MONITOR_HOST3: \c" >>/tmp/send_nsca.out
		if [ -x /usr/local/bin/pingtcp ]; then
			/usr/local/bin/pingtcp $MONITOR_HOST3 22 2>/dev/null
		else
			$PING_BIN $MONITOR_HOST3 >/dev/null 2>&1
		fi
	
		if [ $? -eq 0 ]; then
			$SEND_NSCA_BIN $MONITOR_HOST3 -c $SEND_NSCA_CFG </tmp/nsca_service_data >>/tmp/send_nsca.out
		else
			echo "Unreachable!" >>/tmp/send_nsca.out
		fi
	fi ; unset MHOST
fi

# This next bit is used for testing of new monitor hosts.
# This would be too cumbersome to update many systems but is perfect for a handful
monitor_hosts_file=$OS_DIR/monitor.hosts
#DEBUG# rm $monitor_hosts_file 2>/dev/null #DEBUG# 
if [ -s $monitor_hosts_file ]; then
	for host in `cat $monitor_hosts_file |egrep -v "$MONITOR_HOST|$MONITOR_HOST2"`
	do
		$ECHO_BIN "$host: \c" >>/tmp/send_nsca.out
		$SEND_NSCA_BIN $host -c $SEND_NSCA_CFG </tmp/nsca_service_data >>/tmp/send_nsca.out
	done
fi
sleep 1
#rm /tmp/nsca_service_data /tmp/nsca_checks_running
rm /tmp/nsca_checks_running
