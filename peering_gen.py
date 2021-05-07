#import dnspython as dns
import dns.resolver
import ipaddress
import sys
resolve = dns.resolver.Resolver()

if len(sys.argv) != 6:
    print("Usage: ./peering_gen.py <final config> <base config> <your asn> <the host index> <dns server>")
    print("It's safe to use dn42.unknownts.tk as your host index if the peer is in the index. You can also use your peer's index if they have one")
    sys.exit(1)

write_out = True

global_delimiter = "=" #Dont change unless you want to break everything

end_config = sys.argv[1]#"./test.conf"
base_config = sys.argv[2]#"./base.conf"
your_asn = sys.argv[3]#"4242423315"
host_index = sys.argv[4]#"dn42.unknownts.tk"
dns_server = sys.argv[5]#"63.227.145.132"


def split_destroy(string, split_point, delimiter):
    arr = string.split(delimiter)
    return str(arr[1])

def get_txt_record(hostname, dns):
    
    
    resolve.nameservers = [dns]
    
    result = resolve.query(str(hostname), 'TXT')
    
    return result


choice_arr = []
count = 0
h_index = get_txt_record(host_index, dns_server)

#for val in h_index:
#    print(val.to_text())


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
    host_info = get_txt_record(host, dns_server)
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
            #print(tmp)
            try:
                print(ipaddress.ip_address(tmp))
                full_host_info['$$DN42V6$$'] = tmp
            except:
                #print(tmp)
                if v6_flag == False:
                    v6_flag = True
                elif v6_flag == True:
                    sys.exit(1)
        elif "dn42v6_ll" in line.lower().split(global_delimiter):
            tmp = line.lower().replace("dn42v6_ll"+global_delimiter, "")
            #print(tmp)
            try:
                print(ipaddress.ip_address(tmp))
                full_host_info['$$DN42V6$$'] = tmp
            except:
                #print(str(exp))
                #print(tmp)
                #sys.exit(1)
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
with open(base_config, "r") as f:
    for line in f:
        line_count += 1

replacables = [ "$$DN42V4$$", "$$DN42V6$$", "$$ENDPOINT$$:$$WG_PORT$$", "$$PUBKEY$$" ]
count = 0
new_line = [""]*line_count
with open(base_config, "r") as b_conf:
    for line in enumerate(b_conf):
        for rep in replacables:
            new_line[count] = str(line[1]).replace(str(rep), str(full_host_info[rep]))
            if new_line[count] != line[1]:
                #print(str(new_line[count]))
                break
        count += 1

print(new_line)
if write_out == True:
    with open(end_config, "a") as e_conf:
        for line in new_line:
            e_conf.write(str(line))

#print(full_host_info)