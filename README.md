# nagios_checks
My repository of orignal and tweaked public check scripts
<br>Also included is my original master check script (nsca_checks.sh) which calls many of the OOB plugins/scripts and my own
<br>Enjoy!

* nsca_checks.sh

Would you believe these guys originally used a simple email script to check disk space?
<br>You're welcome.

nsca_checks.sh runs as root every 5 minutes from a cronjob at the 4/9 minutes.
<br>Unless there is no "FIREWALLED" flag in the host.dat file, it creates a data file ready for pickup by a pull script on the Nagios/Naemon/OMD systems.
<br>As a bonus, I'll go ahead and throw those files in this repo as well.
