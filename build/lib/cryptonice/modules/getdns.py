# cryptonice
# getdns.py

import dns.resolver


def getDNSRecord(hostname, record_type):
    record_list = []
    try:
        result = dns.resolver.query(hostname, record_type)
        for ipval in result:
            record_list.append(ipval.to_text())
    except:
        record_list = []

    return record_list


def get_dns(hostname, all_checks):
    print('\nDNS Checks')
    print('-------------------------------------')
    print(f'Analyzing DNS data for {hostname}')
    connection_data = {}
    host_data = {}
    dns_data = {}

    host_data.update({'hostname': hostname})
    connection_data.update({'Connection': hostname})

    print(f'Fetching A records')
    dns_data.update({'A': getDNSRecord(hostname, 'A')})

    if all_checks:
        # Certain DNS records, such as CAA, are usually only present when querying the 'root' domain
        # THIS WON'T WORK FOR DOMAINS THAT HAVE A SUB-DOMAIN AND USE CNAME RECORDS TO DIRECT USERS TO ANOTHER DOMAIN
        root_domain = hostname.replace('www.', '')  # make sure domain name does not have any prefix
        try:
            root_host = root_domain.split('/', 1)[0]  # will remove a path if it exists
        except:
            root_host = root_domain

        print(f'Fetching additional records for {root_host}')
        dns_data.update({'CAA': getDNSRecord(root_host, 'CAA')})
        dns_data.update({'TXT': getDNSRecord(root_host, 'TXT')})
        dns_data.update({'MX': getDNSRecord(root_host, 'MX')})

    connection_data.update({'DNS': dns_data})

    return connection_data


if __name__ == "__main__":
    get_dns()
