This is a small, but neat Bash script that updates [NGINX](https://www.nginx.com/) (real visitor IP) and an [IPTables'](https://en.wikipedia.org/wiki/Iptables) chain with an up-to-date list of [CloudFlare](https://www.cloudflare.com/) IPv4 and IPv6 ranges. This is useful for users who host websites proxied through CloudFlare to hide the direct web server's IP address from the public, but want to automate the process of keeping the CloudFlare IP ranges up-to-date.

If you're hosting a website proxied through CloudFlare, it is recommended that you utilize a firewall such as IPTables to add rules onto the web server to only allow CloudFlare IP ranges on web traffic ports (e.g. `TCP/80` and `TCP/443`) so that users including bots cannot perform port scans and crawl your web server via direct IP. This is where this script comes in handy! With that said, it supports NGINX configuration that'll allow your web applications to retrieve your non-proxied client IP addresses instead of IPs from the CloudFlare proxy servers.

Additionally, I've added testing, backup, and restoring options plus more!

## Installation
While this script automates most of the process, there are a few initial steps required before using it.

### Cron Job & Script Execution
It's best to utilize cron jobs to automatically execute this script. In the cron job below, we update the list *every day at 2:30 AM*. However, you may alter the schedule. I would recommend using a cron job generator such as [this](https://crontab.guru/) if you want to change the schedule.

Since this script should be executed as **root** (or via `sudo`), I recommend editing the root user's cron tab. You can do so using `crontab -e` as root.

Here's a cron job that executes `/root/cf-nginx-iptables-automation/cloudflare.sh` assuming this is the path to the script file.

```bash
# Set $PATH so that the cron job doesn't need absolute paths for each binary.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Cron Job
30 2 * * * /root/cf-nginx-iptables-automation/cloudflare.sh >/dev/null 2>&1
```

### NGINX
By default, the new list of IPs are added to `/etc/nginx/cloudflare.conf`. You will want to add `include /etc/nginx/cloudflare.conf;` into your `/etc/nginx/nginx.conf` file under the `http` section. Here's an example.

```bash
http {
    ...

	include /etc/nginx/cloudflare.conf;

    ...

	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}
```

Afterwards, you may test the configuration with `nginx -t` and reload NGINX with `systemctl reload nginx` (the script has options to do this automatically!).

**Note** - Depending on your Linux distro/OS, you may be able to set `$NGINX_FILE` to something like `/etc/nginx/conf.d/cloudflare.conf` and the steps above wouldn't be needed since `/etc/nginx/conf.d/*.conf` is already included in the main NGINX config. I decided to use another path outside of `conf.d/` since some Linux distros have different file structures for NGINX that doesn't include the `conf.d/` directory.

### IPTables
This script automates the creation and updating of the chain `$IPTABLES_CHAIN`. However, it does not automatically utilize the chain anywhere in the built-in chains such as `INPUT`.

My recommendation is to add a jump to the chain `$IPTABLES_CHAIN` inside of the `INPUT` built-in chain. You can use the following command.

```bash
iptables -A INPUT -j cloudflare
```

You may need to replace `cloudflare` with the chain name you want to use if different (`$IPTABLES_CHAIN`).

Additionally, here are the commands for a basic IPTables firewall utilizing the `cloudflare` chain.

```bash
# Accept lookback.
iptables -A INPUT -i lo -j ACCEPT

# Accept related and established connections.
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Drop invalid connections.
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Jump to our CloudFlare chain if we're using network protocol `TCP` on destination ports 80 and 443.
iptables -A INPUT -j cloudflare
```

I would recommend setting the `INPUT` chain's policy to `ACCEPT` while testing and then setting it to `DROP` when you're absolutely sure things are working. This way your firewall will be utilized properly by dropping packets at the end of the `INPUT` chain that don't match.

```bash
# Set default policy to ACCEPT for `INPUT` chain. This allows all packets in `INPUT` chain unless if matched against a non-accept rule.
iptables -P INPUT ACCEPT

# Set default policy to DROP for `INPUT` chain. This drops all traffic that match no rules in the `INPUT` chain.
iptables -P INPUT DROP
```

**Warning** - If your IPTables rules are incorrectly setup and you set the `INPUT` default policy to `DROP`, it's possible you will lose connection to your server! I would recommend making sure you have access outside of the server's network before performing the above commands!

## Configuration
You may configure settings at the top of the Bash script. Here are the current variables/settings that can be modified.

```bash
# General Configuration
BACKUP_DIR=./backups

# NGINX Configuration
NGINX_ENABLED=1
NGINX_RELOAD=0                          # Reloads NGINX after update if test is successful.
NGINX_BACKUP=1                          # Backups the current config to `$NGINX_BACKUP/nginx_$dateSimple.bak`.
NGINX_RESTORE=1                         # If NGINX test fails, will attempt to restore file. Make sure `$NGINX_BACKUP` is enabled!
NGINX_FILE=/etc/nginx/cloudflare.conf   # Path to the file to output CloudFlare configuration to. This should be the file included in your NGINX config.

# IPTables Configuration
IPTABLES_ENABLED=1
IPTABLES_CHAIN=cloudflare
IPTABLES_BACKUP=1                       # Backups output of `iptables-save` to `$BACKUPS_DIR/iptables_$dateSimple.bak`. 
IPTABLES_SAVE=1                         # Executes `netfilter-persistent save` when finished so rules are re-added on reboot. You must have the `iptables-persistent` package or something similar installed.
IPTABLES_MODE=1                         # Which mode to use. 0 = Flushes chain and re-adds all rules. > 0 = Scans output of `iptables -L <chain>` and if the IP range doesn't exist, adds it.
```

## Inner Workings
### NGINX
When the script adds the IPv4/IPv6 ranges to the NGINX config (`$NGINX_FILE`), it prepends `set_real_ip_from` to each IP range. At the end of the file, it sets `real_ip_header CF-Connecting-IP;`. Here's an example.

```bash
# Auto-Generated. Last Updated: 2024-01-30 12:57:31

# IPv4 ranges
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/13;
set_real_ip_from 104.24.0.0/14;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 131.0.72.0/22;

# IPv6 ranges
set_real_ip_from 2400:cb00::/32;
set_real_ip_from 2606:4700::/32;
set_real_ip_from 2803:f800::/32;
set_real_ip_from 2405:b500::/32;
set_real_ip_from 2405:8100::/32;
set_real_ip_from 2a06:98c0::/29;
set_real_ip_from 2c0f:f248::/32;

# Set Real Header
real_ip_header CF-Connecting-IP;
```

This allows a web application to utilize the user's real IP address instead of the IPs from CloudFlare's proxy servers.

### IPTables
A rule for each CloudFlare IP range is added to a chain (`$IPTABLES_CHAIN`) with the IP/range as the source, `80` and `443` as the destination ports, and `TCP` for the network protocol. These are the typical web ports used when proxying traffic through CloudFlare. With that said, we only match on new or established connections.

Additionally, there are two modes that can be used through the `$IPTABLES_MODE` setting.

* **Mode 0** - Flushes the chain and then re-adds all rules.
* **Mode 1** - Scans the output of `iptables -L $IPTABLES_CHAIN` and if the IP/range doesn't exist, adds it.

The default mode is 0.

Here's an example of output from IPTables on the chain `$IPTABLES_CHAIN` after running the script.

```bash
$ iptables -L cloudflare
Chain cloudflare (0 references)
target     prot opt source               destination         
ACCEPT     tcp  --  173.245.48.0/20      anywhere             ctstate NEW,ESTABLISHED multiport dports http,https
ACCEPT     tcp  --  103.21.244.0/22      anywhere             ctstate NEW,ESTABLISHED multiport dports http,https
ACCEPT     tcp  --  103.22.200.0/22      anywhere             ctstate NEW,ESTABLISHED multiport dports http,https
ACCEPT     tcp  --  103.31.4.0/22        anywhere             ctstate NEW,ESTABLISHED multiport dports http,https
ACCEPT     tcp  --  141.101.64.0/18      anywhere             ctstate NEW,ESTABLISHED multiport dports http,https
ACCEPT     tcp  --  108.162.192.0/18     anywhere             ctstate NEW,ESTABLISHED multiport dports http,https
ACCEPT     tcp  --  190.93.240.0/20      anywhere             ctstate NEW,ESTABLISHED multiport dports http,https
ACCEPT     tcp  --  188.114.96.0/20      anywhere             ctstate NEW,ESTABLISHED multiport dports http,https
ACCEPT     tcp  --  197.234.240.0/22     anywhere             ctstate NEW,ESTABLISHED multiport dports http,https
ACCEPT     tcp  --  198.41.128.0/17      anywhere             ctstate NEW,ESTABLISHED multiport dports http,https
ACCEPT     tcp  --  162.158.0.0/15       anywhere             ctstate NEW,ESTABLISHED multiport dports http,https
ACCEPT     tcp  --  104.16.0.0/13        anywhere             ctstate NEW,ESTABLISHED multiport dports http,https
ACCEPT     tcp  --  104.24.0.0/14        anywhere             ctstate NEW,ESTABLISHED multiport dports http,https
ACCEPT     tcp  --  172.64.0.0/13        anywhere             ctstate NEW,ESTABLISHED multiport dports http,https
ACCEPT     tcp  --  131.0.72.0/22        anywhere             ctstate NEW,ESTABLISHED multiport dports http,https

$ ip6tables -L cloudflare
Chain cloudflare (0 references)
target     prot opt source               destination         
ACCEPT     tcp  --  2400:cb00::/32       anywhere             ctstate NEW,ESTABLISHED multiport dports http,https
ACCEPT     tcp  --  2606:4700::/32       anywhere             ctstate NEW,ESTABLISHED multiport dports http,https
ACCEPT     tcp  --  2803:f800::/32       anywhere             ctstate NEW,ESTABLISHED multiport dports http,https
ACCEPT     tcp  --  2405:b500::/32       anywhere             ctstate NEW,ESTABLISHED multiport dports http,https
ACCEPT     tcp  --  2405:8100::/32       anywhere             ctstate NEW,ESTABLISHED multiport dports http,https
ACCEPT     tcp  --  2a06:98c0::/29       anywhere             ctstate NEW,ESTABLISHED multiport dports http,https
ACCEPT     tcp  --  2c0f:f248::/32       anywhere             ctstate NEW,ESTABLISHED multiport dports http,https
```

## Credits
* [Christian Deacon](https://github.com/gamemann)
* [Carlooosdev](https://github.com/carlooosdev) - Added better logging functionality (PR #[1](https://github.com/gamemann/cf-nginx-iptables-automation/pull/1))