#! /usr/bin/env python
#! /bin/env python
# coding=utf-8

import json;

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
	
	
base_url = 'https://api.cloudflare.com/client/v4/'

def get_user_detail(header):
	user_detail_req = Request(
						base_url+'user',
						headers = header
						);
	user_detail_resp = urlopen(user_detail_req);
	return json.loads(user_detail_resp.read().decode('utf-8'));

def create_zone(root_domain_name, jump_start, type, header):
	data = json.dumps({
					'name': root_domain_name,
					'jump_start': jump_start,
					'type': type
					});
	zone_req = Request(
							base_url+'zones',
							data = data.encode('utf-8'),
							headers = header)
	zone_req.get_method = lambda: 'POST'
	zone_resp = urlopen(zone_req);
	return json.loads(zone_resp.read().decode('utf-8'));
	
def delete_zone(zone_id):
	zone_req = Request(
						base_url+'zones/' + zone_id,
						headers=header
						);
	zone_req.get_method = lambda: 'DELETE';			
	zone_resp = urlopen(zone_req);
	return json.loads(zone_resp.read().decode('utf-8'));

def get_zone(root_domain_name,header):
	zone_req = Request(
						base_url+'zones?name='+root_domain_name+'&status=active&direction=desc&match=all',
						headers=header
						);
	zone_resp = urlopen(zone_req);
	return json.loads(zone_resp.read().decode('utf-8'));

def create_dns_record(zone_id, dns_record_type, dns_record_sub_domain_name_prefix_or_full_domain_name, dns_record_content, dns_record_ttl, dns_record_proxied, header):
	url_path = '{0}{1}{2}'.format(
									base_url+'zones/',
									zone_id,
									'/dns_records'
									);
	data = json.dumps({
					'type': dns_record_type,
					'name': dns_record_sub_domain_name_prefix_or_full_domain_name,
					'content': dns_record_content,
					'ttl':  dns_record_ttl,
					#'priority': dns_record_priority,
					'proxied': dns_record_proxied
					});
	update_req = Request(
							url_path,
							data=data.encode('utf-8'),
							headers=header)
	update_req.get_method = lambda: 'POST'
	update_resp = urlopen(update_req);
	return json.loads(update_resp.read().decode('utf-8'));
	
def delete_dns_record(zone_id,dns_record_id,header):
	record_req = Request(
						base_url+'zones/' + zone_id + '/dns_records/' + dns_record_id,
						headers=header
						);
	record_req.get_method = lambda: 'DELETE';			
	record_resp = urlopen(record_req);
	return json.loads(record_resp.read().decode('utf-8'));

def get_dns_record(zone_id,dns_record_type,dns_record_full_name,header):
	record_req = Request(
						base_url+'zones/' + zone_id + '/dns_records?type='+dns_record_type+'&name='+dns_record_full_name+'&direction=desc&match=all',
						headers=header
						);
	record_resp = urlopen(record_req);
	return json.loads(record_resp.read().decode('utf-8'));

def update_dns_record(zone_id,dns_record_id,dns_record_type,dns_record_sub_domain_name_prefix_or_full_domain_name,dns_record_content,dns_record_ttl,dns_record_proxied,header):
	url_path = '{0}{1}{2}{3}'.format(
									base_url+'zones/',
									zone_id,
									'/dns_records/',
									dns_record_id
									);
	data = json.dumps({
					'type': dns_record_type,
					'name': dns_record_sub_domain_name_prefix_or_full_domain_name,
					'content': dns_record_content,
					'ttl':  dns_record_ttl,
					'proxied': dns_record_proxied
					});
	update_req = Request(
							url_path,
							data=data.encode('utf-8'),
							headers=header);
	update_req.get_method = lambda: 'PUT';
	update_resp = urlopen(update_req);
	return json.loads(update_resp.read().decode('utf-8'));
