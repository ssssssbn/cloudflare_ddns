#! /usr/bin/env python
#! /bin/env python
# coding=utf-8
# Source code on GitHub, link "https://github.com/ssssssbn/cloudflare_ddns", modified based on "https://github.com/AmirAzodi/cloudflare_ddns"
# place cloudflare_ddns_lib.py, cloudflare_api.py, logger.py, cloudflare-ddns.py and cloudflare-ddns.conf on your server (e.g. /usr/local/bin/ or ~/)
# run this command:
# chmod +x /"PATH_TO_FILE"/cloudflare-ddns.py
# open cloudflare-ddns.conf in a text editor and set the necessary parameters.
# (One domain name, one type, one way to get IPv4/6, email address and api_key are required)

#import pdb;

import os;
import json;
import re;
import logging;
import copy;
import time;

try:
	# For Python 3.0 and later
	from urllib.request import urlopen;
	from urllib.request import Request;
	from urllib.error import URLError;
	from urllib.error import HTTPError;
	# import urllib.parse
except ImportError:
	# Fall back to Python 2's urllib2
	from urllib2 import urlopen;
	from urllib2 import Request;
	from urllib2 import HTTPError;
	from urllib2 import URLError;


import cloudflare_api;
import logger;

ipv4_regex = '^(\d{1,3}\.){4}$';
ipv6_regex = '^(([\da-fA-F]{0,4}):){3,8}$';
ttl_range = [1, 120, 300, 600, 900, 1800, 3600, 7200, 18000, 43200, 86400];
type_support = ['A', 'AAAA', 'CNAME'];
			

public_ipv4 = None;
try_get_ipv4 = False;
public_ipv6 = None;
try_get_ipv6 = False;
update = False;
content_header = None;
verify_account = False;
config_file_path = None;
config_file_name = 'cloudflare_ddns.conf';
__config_file_location__ = None;
config = None;
log_file_path = '/tmp/cloudflare_ddns';
log_file_name = 'cloudflare_ddns.log';

class_logger = None;
log = None;

#pdb.set_trace();
def get_ipv4():
	try:
		if config['get_ipv4_by_command']:
			log.info('* Getting public IPv4 address by "get_ipv4_by_command"');
			result = os.popen(config['get_ipv4_by_command']).read().rstrip();
			if not re.match(ipv4_regex, result + '.'):
				log.warning('* The obtained public IPv4 address({0}) by "get_ipv4_by_command" is invalid, please check configured "get_ipv4_by_command" item'.format(
					result));
			else:
				log.info('* Succeed to get IPv4 address({0}) by "get_ipv4_by_command"'.format(
					result));
				return result;

		if config['get_ipv4_via_url']:
			log.info('* Getting public IPv4 address by "get_ipv4_via_url", it may take a while...');
			result = urlopen(Request(config['get_ipv4_via_url'])).read().rstrip().decode('utf-8');
			if not re.match(ipv4_regex, result + '.'):
				log.warning('* The obtained public IPv4 address({0}) by "get_ipv4_via_url" is invalid, please check configured "get_ipv4_via_url" item'.format(
					result));
				log.warning('* Unable to get public IPv4, please check configured "get_ipv4_by_command" and "get_ipv4_via_url" items');
			else:
				log.info('* Succeed to get IPv4 address({0}) by "get_ipv4_via_url"'.format(
					result));
				return result;
	except (Exception, URLError) as e:
		if str(e).find('Network is unreachable') != -1:
			log.error('* Ignore this message if this host does not have a public IPv4, otherwise check your network');
		else:
			log.error('* An exception occurred while getting public IPv4 address. Exception: {0}'.format(
				e));
	return None;

#pdb.set_trace();
def get_ipv6():
	try:
		if config['get_ipv6_by_command']:
			log.info('* Getting public IPv6 address by "get_ipv6_by_command"');
			result = os.popen(config['get_ipv6_by_command']).read().rstrip();
			if not re.match(ipv6_regex, result + ':'):
				log.warning('* The obtained public IPv6 address({0}) by "get_ipv6_by_command" is invalid, please check configured "get_ipv6_by_command" item'.format(
					result));
			else:
				log.info('* Succeed to get IPv6 address({0}) by "get_ipv6_by_command"'.format(
					result));
				return result;

		if not got_ipv6 and config['get_ipv6_via_url']:
			log.info('* Getting public IPv6 address by "get_ipv6_via_url", it may take a while...');
			result = urlopen(Request(config['get_ipv6_via_url'])).read().rstrip().decode('utf-8');
			if not re.match(ipv6_regex, result + ':'):
				log.warning('* The obtained public IPv6 address({0}) by "get_ipv6_via_url" is invalid, please check configured "get_ipv6_via_url" item'.format(
					result));
				log.warning('* Unable to get public IPv6, please check configured "get_ipv6_by_command" and "get_ipv6_via_url" items');
			else:
				log.info('* Succeed to get IPv6 address({0}) by "get_ipv6_via_url"'.format(
					result));
				return result;
	except (Exception, URLError) as e:
		if str(e).find('Network is unreachable') != -1:
			log.error('* Ignore this message if this host does not have a public IPv6, otherwise check your network');
		else:
			log.error('* An exception occurred while getting public IPv6 address. Exception: {0}'.format(
				e));
	return None;

def get_zone_info(domain, root_domain_name, header):
	log.info('* Getting zone information for "{0}"'.format(
		root_domain_name));
	try:
		result = cloudflare_api.get_zone(root_domain_name, header);
		if result['success']:
			log.info('* Succeed to get zone information for "{0}"'.format(
				root_domain_name));
			if result['result_info']['total_count'] != 1:
				if domain['create_if_root_domain_not_exists']:
					log.info('* No active zone for "{0}" found, configuration "create_if_root_domain_not_exists" is "True", creating automatically '.format(
						root_domain_name));
					try:
						#pdb.set_trace();
						zone_create_json = cloudflare_api.create_zone(root_domain_name, False, 'full', header);
						if zone_create_json['success']:
							log.info('* Succeed to create zone for "{0}"'.format(
								root_domain_name));
							return zone_create_json;
						else:
							log.error('Failed to create zone for "{0}", skipping the update for this domain. Errors: {1}, messages: {2}'.format(
								root_domain_name, zone_create_json['errors'], zone_create_json['messages']));
							return None;
					except (Exception, HTTPError) as e:
						log.error('* An exception occurred while creating zone for "{0}", skipping the update for this domain. Exception: {1}'.format(
							root_domain_name, e));
						return None;
				else:
					log.info('* No active zone for "{0}" found, configuration "create_if_root_domain_not_exists" is "False", skipping the update for this domain. Please check configuration and cloudflare settings and try again'.format(
						root_domain_name));
					return None;
			else:
				return result;
		else:
			log.error('* Failed to get zone for "{0}", skipping the update for this domain. Errors: {1}, messages: {2}'.format(
				root_domain_name, result['errors'], result['messages']));
			return None;
	except (Exception, HTTPError) as e:
		log.error('* An exception occurred while getting zone information for: "{0}". Exception: {1}'.format(
			root_domain_name, e));
		return None;

def run():
	global public_ipv4;
	global try_get_ipv4;
	global public_ipv6;
	global try_get_ipv6;
	global update;
	global content_header;
	global verify_account;
	global config_file_path;
	global config_file_name;
	global __config_file_location__;
	global config;
	global log_file_path;
	global log_file_name;
	
	global class_logger;
	global log;

	if not config_file_path:
		config_file_path = os.path.realpath(
			os.path.join(os.getcwd(), os.path.dirname(__file__)))
		__config_file_location__ = os.path.join(config_file_path, config_file_name);
	
	log_file_location = os.path.join(log_file_path, log_file_name);
	if not os.path.exists(log_file_path):
		os.makedirs(log_file_path);
		os.popen('touch {0}'.format(log_file_location));
	elif not os.path.exists(log_file_location):
		os.popen('touch {0}'.format(log_file_location));
	#else:
	#	os.popen('cat /dev/null > {0}'.format(log_file_location));
	
	if not class_logger:
		class_logger = logger.Logger('logger', 
								logging.DEBUG, 
								log_file_path + '/cloudflare_ddns.log', 
								'a', 
								'%(asctime)s-%(levelname)s[line:%(lineno)d]: %(message)s', 
								'utf-8', 
								True, 
								'D', 
								1,
								30);
		log = class_logger.logger;
	
	log.info('------------------------------');
	
	try:
		with open(__config_file_location__, 'r') as config_file:
			try:
				config = json.loads(config_file.read());
			except (Exception, ValueError) as e:
				log.critical('* An exception occurred while loading file "{0}", please check if the file content conforms to the JSON format, the program exit. Exception: {1}'.format(
					__config_file_location__, e));
				exit(0);
	except Exception as e:
		log.critical('* An exception occurred while opening file "{0}", make sure the file exists and you have the permission to read and write it, the program exit. Exception: {1}'.format(
			__config_file_location__, e));
		exit(0);
	
	log_level = None;
	if config['log_level'] not in (0, 1, 2, 3, 4):
		update = True;
		log_level = config['log_level'] = 1;
	else:
		log_level = config['log_level'];
	
	if log_level == 0:
		class_logger.SetLogLevel(logging.DEBUG);
	elif log_level == 1:
		class_logger.SetLogLevel(logging.INFO);
	elif log_level == 2:
		class_logger.SetLogLevel(logging.WARNING);
	elif log_level == 3:
		class_logger.SetLogLevel(logging.ERROR);
	elif log_level == 4:
		class_logger.SetLogLevel(logging.CRITICAL);

	if not config['user']['email'] or not config['user']['api_key']:
		log.critical('* Program is unable to continue without Cloudflare authentication credentials');
		exit(0);
		
	content_header = {'X-Auth-Email': config['user']['email'],
						'X-Auth-Key': config['user']['api_key'],
						'Content-type': 'application/json'};


	for domain in config['domains']:
		zone_json = None;
		get_zone = False;
		new_zone = False;
		next_zone = False;
		root_domain_name = domain['root_domain_name'];
		# check to make sure domain name is specified
		if not root_domain_name:
			log.error('* Missing root_domain name, skipping the update this domain, please check configuration');
			continue;
	
	
		# get domain zone id from CloudFlare if missing
		for host in domain['hosts']:
			# check to make sure host name is specified
			# otherwise move on to the next host
			full_domain_name = None;
			if not host['sub_domain_name_prefix']:
				full_domain_name = root_domain_name;
			else:
				full_domain_name = host['sub_domain_name_prefix'] + '.' + root_domain_name;
	
			types = [];
	
			# iterate over the DNS record types
			for record in host['records']:
				type =record['type'];
				content = record['content'];
				ttl = record['ttl'];
				proxied = record['proxied'];
				
				dns_record_json = None;
				need_update = False;
				# select which IP to use based on DNS record type (e.g. A or AAAA)
				#pdb.set_trace()
				if type not in type_support:
					log.error('* Missing or wrong or unsupported DNS record type: "{0}", skipping the update for type "{1}" of "{2}"'.format(
						type, type, full_domain_name));
					continue;
				elif type == 'A':
					global try_get_ipv4;
					if not try_get_ipv4:
						try_get_ipv4 = True;
						public_ipv4 = get_ipv4();
						
					if record['content']:
						if re.match(ipv4_regex, record['content'] + '.'):
							content = record['content'];
						else:
							log.warning('* The content of type "A" DNS record of "{0}" does not seem to be a valid IPv4 address, skipping the update for type "A" DNS record of "{1}"'.format(
								full_domain_name, full_domain_name));
							continue;
					elif public_ipv4:
						content = public_ipv4;
					else:
						log.warning('* Unable to set type "A" DNS record because no IPv4 address is available, skipping the update for type "A" DNS record of "{0}"'.format(
							full_domain_name));
						continue;
				elif type == 'AAAA':
					if not try_get_ipv6:
						try_get_ipv6 = True;
						public_ipv6 = get_ipv6();
						
					if record['content']:
						if re.match(ipv6_regex, record['content'] + ':'):
							content = record['content'];
						else:
							log.warning('* The content of type "AAAA" DNS record of "{0}" does not seem to be a valid IPv6 address, skipping the update for type "AAAA" DNS record of "{1}"'.format(
								full_domain_name, full_domain_name));
							continue;
					elif public_ipv6:
						content = public_ipv6;
					else:
						log.warning('* Unable to set type "AAAA" DNS record because no IPv6 address is available, skipping the update for type "AAAA" DNS record of "{0}"'.format(
							full_domain_name));
						continue;
				elif type == 'CNAME':
					if record['content']:
						content = record['content'];
					else:
						log.warning('* The content of type "{0}" DNS record is empty, but required, using the default content({1}) to update type "{2}" DNS record of "{3}"'.format(
							type, root_domain_name, type, full_domain_name));
						content = root_domain_name;
				
				if type not in types:
					types.append(type);
				else:
					log.warning('* Type "{0}" DNS record repeated, skipping the update for this DNS record'.format(
						type));
					continue;
					
				#pdb.set_trace();
				if ttl not in ttl_range:
					log.warning('* TTL is invalid and must be 1(Auto), 120 2 min), 300(5 min), 600(10 min), 900(15 min), 1800(30 min), 3600(1 hr), 7200(2 hr ), 18000(5 hr), 43200(12 hr), 86400(1 day), using default value(1(Auto))');
					ttl = 1;
	
				# update ip address/ttl if it has changed since last update
				if record['cloudflare']['content'] != content:
					log.info('* The {0} of DNS recorded as type "{1}" on Cloudflare is different from the local {2}'.format(
						'content' if type == 'CNAME' else 'IP address', type, 'content' if type == 'CNAME' else 'IP address'));
					need_update = True;
				if record['cloudflare']['ttl'] != ttl:
					log.info('* The TTL of DNS recorded as type "{0}" on Cloudflare is different from the local TTL'.format(
						type));
					need_update = True;
					
				
				if not need_update:
					continue;
				#	log.info('* The IP/TTL/content of DNS recorded as type "{0}" on Cloudflare is different from the local public IP/TTL/content, updating type "{1}" DNS record for "{2}"'.format(
				#		type, type, full_domain_name));
				#else:
				#	log.info('* The IP/TTL/content of DNS recorded as type "{0}" on Cloudflare is the same as the local public IP/TTL/content, skipping the update for type "{1}" DNS record of "{2}"'.format(
				#		type, type, full_domain_name));
				#	continue;
					
	
				if not verify_account:
					log.info('* verifying user account');
					try:
						user_detail_json = cloudflare_api.get_user_detail(content_header);
						if user_detail_json['success']:
							log.info('* Succeed to verify user account');
							verify_account = True;
						else:
							log.error('* Failed to verify user account, please check user account, the program exit');
							exit(0);
					except (Exception, HTTPError) as e:
						log.error('* An exception occurred while verifying user account, the program exit. Exception: {0}'.format(
							e));
						exit(0);
	
				#get domain information from Cloudflare
				if not get_zone:
					zone_json = get_zone_info(domain, root_domain_name, content_header);
					if not zone_json:
						next_zone = True;
						break;
					elif not isinstance(zone_json['result'], list):
						new_zone = True;
					get_zone = True;
	
	
				if not need_update:
					continue;
	
				#get DNS record information from Cloudflare
				log.info('* Getting type "{0}" DNS record of "{1}"'.format(
					type, full_domain_name));
				try:
					#pdb.set_trace();
					dns_record_json = cloudflare_api.get_dns_record(zone_json['result']['id'] if new_zone else zone_json['result'][0]['id'], type, full_domain_name, content_header);
					if dns_record_json['success']:
						log.info('* Succeed to get type "{0}" DNS record of "{1}"'.format(
							type, full_domain_name));
					else:
						log.warning('* Failed to get type "{0}" DNS record of "{1}", skipping the update for type "{2}" DNS record of "{3}"'.format(
							type, full_domain_name, type, full_domain_name));
						continue;
				except (Exception, HTTPError) as e:
					log.error('* An exception occurred while getting type "{0}" DNS record of "{1}", skipping the update for type "{2}" DNS record of "{3}". Exception: {4}'.format(
						type, full_domain_name, type, full_domain_name, e));
					continue;
	
				
	
				try:
					if dns_record_json['result_info']['total_count'] < 1:
						if host['create_if_the_record_not_exists']:
							log.info('* No type "{0}" DNS record of "{1}" found, configuration "create_if_the_record_not_exists" is "True", creating DNS record(type: {2}, name: {3}, content: {4}, ttl: {5}) automatically'.format(
								type, root_domain_name, type, full_domain_name, content, ttl));
							try:
								dns_record_create_json = cloudflare_api.create_dns_record(zone_json['result']['id'] if new_zone else zone_json['result'][0]['id'], type, full_domain_name, content, ttl, proxied, content_header);
								if dns_record_create_json['success']:
									update = True;
									#dns_record_json['result'][0]['id'] = dns_record_create_json['result']['id'];
									record['cloudflare']['content'] = content;
									record['cloudflare']['ttl'] = ttl;
									record['cloudflare']['proxied'] = proxied;
									log.info('* Succeed to create DNS record(id: {0}, type: {1}, name: {2}, content: {3}, ttl: {4}, proxied: {5})'.format(
										dns_record_create_json['result']['id'], type, full_domain_name, content, ttl, proxied));
								else:
									log.warning('* Failed to create DNS record(type: {0}, name: {1}, content: {2}, ttl: {3}, proxied: {4}). Errors:{5}, messages:{6}'.format(
										type, full_domain_name, content, ttl, proxied, dns_record_create_json['errors'], dns_record_create_json['messages']));
							except (Exception, HTTPError) as e:
								log.error('* An exception occurred while creating DNS record(type: {0}, name: {1}, content: {2}, ttl: {3}, proxied: {4}), skipping the update this DNS record. Exception:{5}'.format(
									type, full_domain_name, content, ttl, proxied, e));
						else:
							log.warning('* No type "{0}" DNS record "{1}" found, configuration "create_if_the_record_not_exists" is "False", skipping the update this DNS record. Please check configuration and cloudflare settings and try again'.format(
								type, root_domain_name));
						continue;
					elif dns_record_json['result_info']['total_count'] > 1:
						if host['delete_if_the_same_type_of_record_repeated']:
							log.info('* Type "{0}" DNS record of "{1}" is not unique, configuration "delete_if_the_same_type_of_record_repeated" is "True", using the first DNS record and deleting others'.format(
								type, root_domain_name));
							for index in range(dns_record_json['result_info']['total_count']):
								if index == 0:
									log.info('* Keep the first DNS record(id: {0}, type: {1}, name: {2}, content: {3}, ttl: {4}, proxied: {5})'.format(
										dns_record_json['result'][index]['id'], dns_record_json['result'][index]['type'], dns_record_json['result'][index]['name'], dns_record_json['result'][index]['content'], dns_record_json['result'][index]['ttl'], dns_record_json['result'][index]['proxied']));
									continue;
								else:
									log.info('* Deleting DNS record(id: {0}, type: {1}, name: {2}, content: {3}, ttl: {4}, proxied: {5})'.format(
										dns_record_json['result'][index]['id'], dns_record_json['result'][index]['type'], dns_record_json['result'][index]['name'], dns_record_json['result'][index]['content'], dns_record_json['result'][index]['ttl'], dns_record_json['result'][index]['proxied']));
									try:
										dns_record_delete_json = cloudflare_api.delete_dns_record(zone_json['result']['id'] if new_zone else zone_json['result'][0]['id'], dns_record_json['result'][index]['id'], content_header);
										if dns_record_delete_json['success']:
											log.info('* Succeed to delete type "{0}" DNS record(id: {1})'.format(
												type, dns_record_delete_json['result']['id']));
										else:
											log.warning('* Failed to delete type "{0}" DNS record(id: {1}). Errors:{2}, messages:{3}'.format(
												type, dns_record_json['result'][index]['id'], dns_record_delete_json['errors'], dns_record_delete_json['messages']));
											break;
									except (Exception, HTTPError) as e:
										log.error('* An exception occurred while deleting type "{0}" DNS record(id: {1}), gave up deleting type "{2}" DNS record(id: {3}) for "{4}". Exception:{5}'.format(
											type, dns_record_json['result'][index]['id'], type, dns_record_json['result'][index]['id'], full_domain_name, e));
										break;
						else:
							log.warning('* Type "{0}" DNS record "{1}" is not unique, configuration "delete_if_the_same_type_of_record_repeated" is "False", using the first DNS record'.format(
								type, root_domain_name));
				except (Exception, HTTPError) as e:
					log.error('* An exception occurred while handling DNS records, skipping the update for type "{0}" DNS record of "{1}". Exception: {2}'.format(
						type, full_domain_name, e));
					continue;
					
				log.info('* Updating type "{0}" DNS record for "{1}"'.format(
					type, full_domain_name));
				try:
					#pdb.set_trace();
					if not record['cloudflare']['content'] and content == dns_record_json['result'][0]['content'] and ttl == dns_record_json['result'][0]['ttl'] and proxied == dns_record_json['result'][0]['proxied']:
						update = True;
						record['cloudflare']['content'] = content;
						record['cloudflare']['ttl'] = ttl;
						record['cloudflare']['proxied'] = proxied;
						log.info('* Succeed to update DNS record(id: {0}, type: {1}, name: {2}, content: {3}, ttl: {4}, proxied: {5})'.format(
							dns_record_json['result'][0]['id'], type, full_domain_name, content, ttl, proxied));
						continue;
					update_res_json = cloudflare_api.update_dns_record(zone_json['result']['id'] if new_zone else zone_json['result'][0]['id'], dns_record_json['result'][0]['id'], type, full_domain_name, content, ttl, proxied, content_header);
					if update_res_json['success']:
						update = True;
						record['cloudflare']['content'] = content;
						record['cloudflare']['ttl'] = ttl;
						record['cloudflare']['proxied'] = proxied;
						log.info('* Succeed to update DNS record(id: {0}, type: {1}, name: {2}, content: {3}, ttl: {4}, proxied: {5})'.format(
							update_res_json['result']['id'], type, full_domain_name, content, ttl, proxied));
					else:
						log.warning('* Failed to update type "{0}" DNS record(id: {1}, type: {2}, name: {3}). Errors: {4}, messages: {5}'.format(
							type, dns_record_json['result'][0]['id'], type, full_domain_name, update_res_json['errosr'], update_res_json['messages']));
				except (Exception, HTTPError) as e:
					log.error('* An exception occurred while updating DNS record(id: {0}, type: {1}, name: {2}). Exception: {3}'.format(
						dns_record_json['result'][0]['id'], type, full_domain_name, e));
	
	
			if next_zone:
				continue;
			
			
			if host['delete_the_other_unused_type_of_record']:
				log.info('* Configuration "delete_the_other_unused_type_of_record" is "True", deleting other unused type DNS record for "{0}" if exists'.format(
					full_domain_name));
					
				if not get_zone:
					zone_json = get_zone_info(domain, root_domain_name, content_header);
					if not zone_json:
						continue;
					elif not isinstance(zone_json['result'], list):
						new_zone = True;
					get_zone = True;
					
				#pdb.set_trace();
				delete_type = copy.deepcopy(type_support);
				for type in types:
					try:
						del delete_type[delete_type.index(type)];
					except Exception:
						pass;
				if len(delete_type) > 0:
					for type in delete_type:
						try:
							type_record_json = cloudflare_api.get_dns_record(zone_json['result']['id'] if new_zone else zone_json['result'][0]['id'], type, full_domain_name, content_header);
							if type_record_json['success']:
								for delete_record_json in type_record_json['result']:
									log.info('* Deleting type "{0}" DNS record(id: {1})'.format(
										type, delete_record_json['id']));
									try:
										type_record_delete_json = cloudflare_api.delete_dns_record(zone_json['result']['id'] if new_zone else zone_json['result'][0]['id'], delete_record_json['id'], content_header);
										if type_record_delete_json['success']:
											log.info('* Succeed to delete type "{0}" DNS record(id: {1})'.format(
												type, delete_record_json['id']));
										else:
											log.warning('* Failed to delete type "{0}" DNS record(id: {1}). Errors: {2}, messages: {3}'.format(
												type, delete_record_json['id'], type_record_delete_json['errors'], type_record_delete_json['messages']));
									except (Exception, HTTPError) as e:
										log.error('* An exception occurred while deleting type "{0}" DNS record(id: {1}), gave up deleting this DNS record. Exception: {2}'.format(
											type, delete_record_json['id'], e));
							else:
								log.warning('* Failed to get type "{0}" DNS records for "{1}", gave up deleting DNS records'.format(
									type, full_domain_name));
						except (Exception, HTTPError) as e:
							log.error('* An exception occurred while deleting type "{0}" DNS records, gave up deleting type "{1}" DNS records. Exception: {2}'.format(
								type, type, e));
				
				host['delete_the_other_unused_type_of_record'] = False;
				update = True;
	
	
	
	# if any DNS records were updated, update the config file accordingly
	if update:
		try:
			with open(__config_file_location__, 'w') as config_file:
				json.dump(config, config_file, indent = 1, sort_keys = True);
		except Exception as e:
			log.error('* An exception occurred while writing the configuration to the file "{0}". Exception: {1}'.format(
				__config_file_location__, e));
		log.info('* Updates completed. Bye.');
	else:
		log.info('* Nothing to update. Bye.');
		
	public_ipv4 = None;
	try_get_ipv4 = False;
	public_ipv6 = None;
	try_get_ipv6 = False;
	update = False;

if __name__ == '__main__':
	try:
		while True:
			run();
			#pdb.set_trace();
			if config['check_interval']:
				time.sleep(config['check_interval']);
			else:
				break;
	except Exception as e:
		log.error('* An exception occurred while running, the program exit. Exception: {0}'.format(
			e));
	exit(0);
