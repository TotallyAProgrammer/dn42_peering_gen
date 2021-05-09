#!/usr/bin/env python3

import re
import sys
import argparse
import ipaddress
import dns.resolver

resolve = dns.resolver.Resolver()

parser = argparse.ArgumentParser(description='DN42 Assisted Remote Peering System (DARPS)')
## The lighthouse is still Work in progress!
## Examples:
## ./peering_gen.py -s 1.omaha.nebraska.central.unknownts.tk -d 1.1.1.1 -t wireguard_template.conf -a 4242423770 -c YOUR_DN42_IPv4=172.172.172.172 -c YOUR_DN42_IPv6LL=fd80::100/128 -c NICKNAME=Zane  -q
## ./peering_gen.py -s 1.omaha.nebraska.central.unknownts.tk -d 1.1.1.1 -t wireguard_template.conf -a 4242423770 -c YOUR_DN42_IPv4=172.172.172.172 -c YOUR_DN42_IPv6LL=fd80::100/128 -c NICKNAME=Zane  -q
parser.add_argument('-l', '--remote-lighthouse', dest='remote_lighthouse', metavar='REMOTE_LIGHTHOUSE', help="remote lighthouse (index of all remote nodes)")
parser.add_argument('-s', '--seeder-domain', dest='seeder_domain', help='domain name of the node you want to peer')
parser.add_argument('-q', '--query-peering-info', dest='query_peering_info', help='show the remote node peering params and exit', action='store_true')
parser.add_argument('-t', '--template', dest='template_file', metavar='INPUT', help='input template file')
parser.add_argument('-o', '--output', dest='output_file', metavar='OUTPUT', help='output file', default=None)
parser.add_argument('-d', '--custom-dns', dest='dns_server', metavar='DNS', help='custom DNS server to query', default=None)
parser.add_argument('-r', '--remote-param', dest='remote_params', metavar='REMOTE_PARAM', help='allow usage of a custom remote parameter', action='append')
parser.add_argument('-a', '--asn', dest='local_asn', metavar='YOUR_ASN', help='your own DN42 ASN (can be used in templates)', type=int)
parser.add_argument('-c', '--custom', dest='custom_params', metavar='KEY_VAL', help='custom key/value for your template', action='append', default=[])
parser.add_argument('--local-port-format', dest='wireguard_port_format', metavar='STRING', help='local wireguard port prefix (default: 5xxxx)', default='5xxxx')
args = parser.parse_args()

allowed_params = ['CLEARNET', 'WG_PORT', 'DN42v4', 'DN42v6', 'DN42v6_LL', 'PUBKEY', 'MP_BGP']
if args.remote_params:
    allowed_params += args.remote_params

# output_file = sys.argv[1]#"./test.conf"
# template_file = sys.argv[2]#"./base.conf"
# your_asn = sys.argv[3]#"4242423315"
# seeder_domain = sys.argv[4]#"dn42.unknownts.tk"
# dns_server = sys.argv[5]#"63.227.145.132"


def filter_by_keys(lst, keys):
    return [k for k in lst if k.keys() & keys]

def get_values(lst, key, onlyFirst=False):
    result = []
    for e in lst:
        for k in e:
            if k == key: result.append(e[k])
    if onlyFirst:
        return result[0]
    return result

def set_value(lst, key, value):
    lst = [{k: v for k, v in d.items() if k != key} for d in lst]
    lst.append({key: value})
    return lst

def delete_value(lst, key):
    lst = [k for k in lst if not k.keys() & [key]]
    return lst

def keyval_to_dict(keyval):
    match = re.match('^(?P<key>[A-z].+)=(?P<value>.+)$', str(keyval).strip('"'))
    return {match['key']: match['value']}

def parse_keyval_list(keyvals):
    result = []
    for record in keyvals:
        result.append(keyval_to_dict(record))
    return result

def get_txt_records(hostname, dns_server=None):
    if dns_server:
        resolve.nameservers = [dns_server]
    result = []

    # result = ['ASN=4242423315','DN42v4=172.22.167.67','DN42v6=fd62:e667:840a::2','DN42v6_LL=fe80::ade1','PUBKEY=7SAw34vmYtgyEi05f78nc5kbEiCGvVTeqa3xdN+0034=','WG_PORT=5xxxx','CLEARNET=1.omaha.nebraska.central.unknownts.tk','MP_BGP=true','DARPS=v1']
    query_result = resolve.query(str(hostname), 'TXT')
    result = parse_keyval_list(query_result)
    return result

def generate_shortasn(asn, charcnt=4):
    asn = str(asn)
    return asn[-charcnt:]

def generate_port(asn, str_format):
    asn = str(asn)
    str_format = str(str_format)
    digits = str_format.count('x')
    str_format = str_format.replace('x','')
    return str_format + generate_shortasn(asn, digits)

def show_peering_info(records):
    for e in records:
        for k in e:
            if k == 'WG_PORT':
                # Show hint about ports and asn
                remote_port = generate_port(args.local_asn, e[k])
                e[k] = '%s (includes last %s digits of your ASN)' % (remote_port, e[k].count('x'))
            print(k.rjust(16, ' '), ':', e[k])
    print('')
    print('You can also get these details with:   dig TXT %s' % args.seeder_domain)

def replace_variable(variable_name, value, content):
    regex = '({{\s*%s\s*}})'
    return re.sub((regex % variable_name), value, content)

def generate_template(template_file, keyvals):
    regex = '({{\s*%s\s*}})'
    tpl = open(template_file,'r').read()
    for vars in keyvals:
        for varname in vars:
            tpl = replace_variable(varname, vars[varname], tpl)
    return tpl

def add_automatic_fields(keyvals):
    keyvals = set_value(keyvals, 'LOCAL_WG_PORT', generate_port(get_values(keyvals, 'ASN', True), args.wireguard_port_format))
    keyvals = set_value(keyvals, 'LOCAL_SHORTASN', generate_shortasn(args.local_asn))
    keyvals = set_value(keyvals, 'REMOTE_WG_PORT', generate_port(args.local_asn, get_values(keyvals, 'WG_PORT', True)))
    keyvals = delete_value(keyvals, 'WG_PORT')
    keyvals = set_value(keyvals, 'REMOTE_SHORTASN', generate_shortasn(get_values(keyvals, 'ASN', True)))
    return keyvals

txt_records = get_txt_records(args.seeder_domain, args.dns_server)
if args.query_peering_info:
    show_peering_info(txt_records)
    exit(0)

template_variables = add_automatic_fields(txt_records + parse_keyval_list(args.custom_params))
if args.template_file:
    tpl = generate_template(args.template_file, template_variables)
    print(tpl)
    exit(0)



print('Previous code; exiting...')
exit(0)

choice_arr = []
count = 0
h_index = get_txt_record(args.seeder_domain, args.dns_server)
print(h_index)

#for val in h_index:
#    print(val.to_text())

## TODO: what is this?
for val in h_index:
    count += 1
    data = val.to_text().replace("\"", "").split(global_delimiter)
    data.insert(0, count)
    #print(data)
    option_total = len(data)
    choice_arr.append(data)

#for sub_arr in choice_arr:
#    print(sub_arr)
choice_data = []
i = 0
print(data)
for sub_arr in choice_arr:
    i += 1
    print(str(i) + ": " + str(sub_arr[2]))

def retr_host():
    tmp_arr = []
    #print(len(choice_arr))
    while True:
        choice = input("Host selection: ")
        if 0 < int(choice) <= len(choice_arr):
            break
    top = choice_arr[int(choice)-1]
    host = top[2]
    #print(host)
    host_info = get_txt_record(host, args.dns_server)
    for info in host_info:
        #print(info.to_text())
        tmp_arr.append(info.to_text())
    choice_data.append(tmp_arr)

retr_host()
full_host_info = {}
v6_flag = False
for val in choice_data:
    for subset in val:
        line = subset.replace("\"", "")
        #print(line)
        #print(line.lower())
        if "dn42v6" in line.lower().split(global_delimiter):
            tmp = line.lower().replace("dn42v6"+global_delimiter, "")
            try:
                print(ipaddress.ip_address(tmp))
                full_host_info['$$DN42V6$$'] = tmp
            except:
                if v6_flag == False:
                    v6_flag = True
                elif v6_flag == True:
                    sys.exit(1)
        elif "dn42v6_ll" in line.lower().split(global_delimiter):
            tmp = line.lower().replace("dn42v6_ll"+global_delimiter, "")
            try:
                print(ipaddress.ip_address(tmp))
                full_host_info['$$DN42V6$$'] = tmp
            except:
                if v6_flag == False:
                    v6_flag = True
                elif v6_flag == True:
                    sys.exit(1)
        elif "dn42v4" in line.lower().split(global_delimiter):
            tmp = line.lower().replace("dn42v4"+global_delimiter, "")
            #print(tmp)
            try:
                #print(ipaddress.ip_address(tmp))
                full_host_info['$$DN42V4$$'] = tmp
            except:
                #print(tmp)
                sys.exit(1)
        elif "asn" in line.lower().split(global_delimiter):
            tmp = line.lower().replace("asn"+global_delimiter, "")
            #print(tmp)
            try:
                full_host_info['asn'] = tmp
            except:
                #print(tmp)
                sys.exit(1)
        elif "pubkey" in line.lower().split(global_delimiter):
            #tmp = line.lower().replace("pubkey:", "")
            tmp  = split_destroy(line, "pubkey"+global_delimiter, global_delimiter)
            #print(tmp)
            try:
                full_host_info['$$PUBKEY$$'] = tmp
            except:
                #print(tmp)
                sys.exit(1)
        elif "wg_port" in line.lower().split(global_delimiter):
            tmp = line.lower().replace("wg_port"+global_delimiter, "")
            #print(tmp)
            try:
                full_host_info['$$WG_PORT$$'] = tmp
            except:
                #print(tmp)
                sys.exit(1)
        elif "clearnet" in line.lower().split(global_delimiter):
            tmp = line.lower().replace("clearnet"+global_delimiter, "")
            #print(tmp)
            try:
                full_host_info['$$ENDPOINT$$'] = tmp
            except:
                #print(tmp)
                sys.exit(1)

full_host_info["$$ENDPOINT$$:$$WG_PORT$$"] = str(full_host_info["$$ENDPOINT$$"]) + ":" + str(full_host_info["$$WG_PORT$$"])

line_count = 0
with open(args.template_file, "r") as f:
    for line in f:
        line_count += 1

replacables = [ "$$DN42V4$$", "$$DN42V6$$", "$$ENDPOINT$$:$$WG_PORT$$", "$$PUBKEY$$" ]
count = 0
new_line = [""]*line_count
with open(args.template_file, "r") as b_conf:
    for line in enumerate(b_conf):
        for rep in replacables:
            new_line[count] = str(line[1]).replace(str(rep), str(full_host_info[rep]))
            if new_line[count] != line[1]:
                #print(str(new_line[count]))
                break
        count += 1

print(new_line)
if args.output_file:
    with open(args.output_file, "a") as e_conf:
        for line in new_line:
            e_conf.write(str(line))

#print(full_host_info)
