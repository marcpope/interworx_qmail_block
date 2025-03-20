#qmail blocker for Interworx

If you have qmail and apf firewall like Interworx does, this script will block /24 subnets of hacking attempts. It monitors for AUTH failed in the /var/log/smtp/current folder and if the same IP gets more than THRESHOLD invalid, it will add them to apf firewall for the BLOCK_DURATION time and then remove them after that expires. The TIME_WINDOW is how long it should count bad logins over the past seconds.

to run, download script, make it executable, and nohup it:
```
nohup /location/of/script/qmail-block.sh
```
