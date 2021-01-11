import socket
import pythonwhois
from ipClass import IP
import re
import ssl
import OpenSSL

class UrlDomain:
    def __init__(self, domainstr, url):
        self.domain = domainstr
        self.urllist = [url]
        self.ip = []
        self.cert = None
        self.whois = None

        self.domain_query()

    def domain_query(self):
        # try:
        ip_regex = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        print(self.domain)
        if re.findall(ip_regex, self.domain) == [] and self.domain[0] == ".":
            
            self.ip = []

        elif re.findall(ip_regex, self.domain) == [] and self.domain[0] != ".":
            try:
                query = socket.gethostbyname_ex(self.domain)
                for ip in query[2]:
                    ip_addr = IP(ip)
                    ip_addr.get_info()
                    self.ip.append(ip_addr)
                self.get_cert()
            except:
                self.ip = [] 
        else:
            self.ip = IP(self.domain)
            self.ip.get_info()
        # except Exception as e:
        #     print(e)
        #     return

    def get_cert(self):
        if self.domain[0] == ".":
            domain = self.domain[1:]
        else:
            domain = self.domain
        try:
            self.cert = ssl.get_server_certificate((domain, 443))
            self.cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.cert)
            print(self.cert)
        except:
            self.cert = None

    def add_url(self, Url):
        self.urllist.append(Url)

    def domain_info(self):
        try:
            self.whois = pythonwhois.get_whois(self.domain)
            print(self.whois)
        except Exception as e:
            print("Error occured at DomainClass: " + str(e))


class BaseDomain(UrlDomain):

    def __init__(self, domainstr):
        super().__init__(domainstr, url=None)
        self.domain_info()
