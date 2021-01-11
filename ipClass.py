from ipwhois import IPWhois
import socket
from ipaddress import ip_network, ip_address

#Read the IP relay blacklist file
ipblacklist_file = open("ipblacklist.txt", "r")
ip_blacklist = []
line = ipblacklist_file.readline().split(";")[0][:-1]
while line:
    ip_blacklist.append(line)
    line = ipblacklist_file.readline().split(";")[0][:-1]

class IP:
    def __init__(self, ipstr):
        self.ip = ipstr
        self.public = self.assert_public()

        #information on IP address
        self.queried = False
        self.reverse = ""

        self.country = ""
        self.address = "Unavailable"
        self.name = "Unavailable"
        self.description = ""
        self.asn_descrip = ""
        self.created = "Unavailable"
        self.updated = "Unavailable"
        self.emails = []
        self.malicious = False

        self.clean_ipv6_encap()
        self.check_blacklist()

        # if self.public:
        #     print(self.ip + " queried")
        #     self.get_info()
        # else:
        #     print(self.ip + "not queried")
        #     self.country = "Private IP"
    def check_blacklist(self):
        for black_ip in ip_blacklist:
            black_net = ip_network(black_ip)
            if ip_address(self.ip) in black_net:
                print('\n===NOTE===')
                print(self.ip, "MALICIOUS SMTP!\n")
                self.malicious = True


    def get_info(self):
        print("Querying: " + str(self.ip))
        ip_query = IPWhois(self.ip)
        full_result = ip_query.lookup_whois()
        results = full_result['nets']

        self.country = full_result['asn_country_code']
        self.asn_descrip = full_result['asn_description']

        for net in results:
            if net['name'] is not None and self.name == "Unavailable":
                self.name = net['name']
            # if net['country'] is not None and self.country == "":
            #     self.country += net['country']
            #     if net['state'] is not None:
            #         self.country += ", " + net['state']
            #     if net['city'] is not None:
            #         self.country += ", " + net['city']
            if net['address'] is not None and self.address == "Unavailable":
                self.address = net['address']
                if net['postal_code'] is not None:
                    self.address += " (" + net['postal_code'] + ")"
            if net['created'] is not None and self.created == "Unavailable":
                self.created = net['created']
            if net['updated'] is not None and self.updated == "Unavailable":
                self.updated = net['updated']
            if net['description'] is not None and self.description == "Unavailable":
                self.description = net['description']

            if net['emails'] is not None:
                self.emails.extend(net['emails'])

        try:
            self.reverse = socket.gethostbyaddr(self.ip)[0]
            self.queried = True
        except:
            self.reverse = "None"
            self.queried = True

    def assert_public(self):
        split_ip = self.ip.split(".")
        if split_ip[0] == "192" and split_ip[1] == "168":
            return False
        elif split_ip[0] == "10":
            return False
        elif split_ip[0] == "172" and (16 <= int(split_ip[1]) <= 32):
            return False
        elif self.ip == "127.0.0.1":
            return False
        else:
            return True

    def clean_ipv6_encap(self):
        if ":ffff" in self.ip:
            self.ip = self.ip.split(":")[-1]
        else:
            return

    def create_str(self):
        output_str = ""

        output_str += "IP ADDRESS: " + self.ip + "\n"
        output_str += "COUNTRY: " + self.country + "\n"
        output_str += "ADDRESS: " + self.address + "\n"
        output_str += "CREATED: " + self.created + "\n"
        output_str += "UPDATED: " + self.updated + "\n"

        return output_str


