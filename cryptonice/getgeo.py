import geoip2.database
from pathlib import Path

def getlocation(ip_address):
    # The directory containing this file
    thispath = Path(__file__).parent
    results = {}

    try:
        with geoip2.database.Reader(str(thispath) + '/maxmind/GeoLite2-Country.mmdb') as reader:
            response = reader.country(ip_address)
            ip_isocode = response.country.iso_code
            ip_country = response.country.name

        with geoip2.database.Reader(str(thispath) + '/maxmind/GeoLite2-ASN.mmdb') as reader:
            response = reader.asn(ip_address)
            ip_asn = response.autonomous_system_number
            ip_org = response.autonomous_system_organization


        results.update({'iso_code': ip_isocode})
        results.update({'ip_country': ip_country})
        results.update({'ip_asn': ip_asn})
        results.update({'ip_org': ip_org})

    except:
        results.update({'error': 'Unable to lookup geolocation information. Possible missing Maxmind database files.'})
        
    return results
