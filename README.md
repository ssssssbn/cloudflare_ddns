# Yet Another Dynamic DNS Client 
*Dynamic DNS Client for CloudFlare written in Python*

Unless you have a static public IP address, this is probably the most reliable way to ensure your servers are always accessible to you over the Internet.

#####Features:
* Supports IPv4 and IPv6 records (A, AAAA)
* Supports multiple domains with multiple hosts per domain
* Simultaneous IPv4 and IPv6 support for single host
* No third party libraries used. Only standard python libs.
* Works with Python 2 and 3
* Designed to run on any OS that supports Python (i.e. not dependent on any OS specific tools)
* Only makes changes to CloudFlare's zone files when necessary. Stores last IP address of each host in config file.
* Simple JSON config file
* ~~Automatically collects and saves the zone and host IDs if missing.~~

#####Simple JSON config file:
```javascript
{
 "check_interval": 0, # Set the check interval in seconds and ensure that the script runs on the backend, you can also set it 0(off) and use "crontab" to set up a scheduled run.
 "domains": [
  {
   "create_if_root_domain_not_exists": true, # If your root domain name has not been added to Cloudflare, setting it to True will automatically help you add the root domain name to Cloudflare
   "hosts": [
    {
     "create_if_the_record_not_exists": true, # If the record you want to update does not exist, set it True to help you create that record
	 "delete_if_the_same_type_of_record_repeated": true, # If there is a duplicate of the type of record you want to update, set it "True" to help you delete extra records
     "delete_the_other_unused_type_of_record": false, # If you no longer use other types of records, such as using only type A and not using AAAA and CNAME types, set True to help you delete AAAA and CNAME types
     "records": [
      {
       "cloudflare": {
        "content": "", # Store Cloudflare content after each update, if different from Cloudflare, leave it blank
        "proxied": false, # Store Cloudflare proxied status after each update, if different from Cloudflare, set it false
        "ttl": 0 # Store Cloudflare ttl after each update, if different from Cloudflare, set it 0
       }, 
       "content": "", # Set for CNAME type, blank it to update the root domain name
       "proxied": false, # Set it True to make the Cloudflare icon orange(using Cloudflare proxy)
       "ttl": 1, # TTL is only valid in 1, 120, 300, 600, 900, 1800, 3600, 7200, 18000, 43200, 86400(in second)
       "type": "RECORD_TYPE_HERE e.g. A/AAAA/CNAME" # Support A / AAAA / CNAME type, Required
      }
     ], 
     "sub_domain_name_prefix": "SUB_DOMAIN_NAME_HERE e.g. www" # Blank it to update root domain name
    }
   ], 
   "root_domain_name": "ROOT_DOMAIN_NAME_HERE e.g. example.com" # Required
  }
 ], 
 "get_ipv4_by_command": "LINUX_COMMAND_TO_GET_IPv4_HERE", # Blank it if you don’t understand
 "get_ipv4_via_url": "URL_TO_GET_IPv4_HERE", # You can use "http://ipv4.icanhazip.com" but I can't ensure its security
 "get_ipv6_by_command": "LINUX_COMMAND_TO_GET_IPv6_HERE", # Blank it if you don’t understand
 "get_ipv6_via_url": "URL_TO_GET_IPv6_HERE", # You can use "http://ipv6.icanhazip.com" but I can't ensure its security
 "log_level": 1, # 0 Debug, 1 Info, 2 Warning, 3 Error, 4 Critical, upwards include
 "user": {
  "api_key": "CLOUDFLARE_API_KEY_HERE", # Your Cloudflare Global API KEY, Required
  "email": "CLOUDFLARE_EMAIL_HERE" # Your Cloudflare email, Required
 }
}
```

#####Getting Started:
1. Download and place the ```cloudflare_ddns.py```, ```cloudflare_api.py```, ```logger.py``` and ```cloudflare_ddns.conf``` files somewhere on your server (e.g. ```/usr/local/bin/``` or ```~/```). 
2. Open the ```cloudflare_ddns.conf``` file in a text editor and specify your email address, API key, domain name, host name, record type and a way to get IPv4/6.
3. Set +x permission to the script for your user by running ```chmod +x /PATH_TO_FILE/cf-ddns.py```
~~4. Run ```crontab -e``` and append this line to it: ```*/5 * * * * /PATH_TO_FILE/cf-ddns.py >/dev/null 2>&1```. be sure to change the path to match your setup.~~
5. That's it :) 

#####Test on:
Ubuntu 19.10
Debian 10
Centos 7.6

#####Miscellaneous:
* New features and code improvements are welcomed
* If you find a bug please create a GitHub issue for it
