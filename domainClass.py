import socket
import pythonwhois
from ipClass import IP
import re
import ssl
import OpenSSL
from datetime import datetime

class UrlDomain:
    def __init__(self, domainstr, url):
        self.domain = domainstr
        self.urllist = [url]
        self.ip = []
        self.cert = None
        self.whois = None
        self.date = None
        self.subject = None
        self.issuer = None

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
            conn = ssl.create_connection((domain, 443))
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            sock = context.wrap_socket(conn, server_hostname=domain)
            self.cert = ssl.DER_cert_to_PEM_cert(sock.getpeercert(True))
            # self.cert = ssl.get_server_certificate((domain, 443))
            self.cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.cert)
            self.date = (
            datetime.strptime(self.cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ').strftime("%Y/%m/%d"),
            datetime.strptime(self.cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ').strftime("%Y/%m/%d"))
            print(self.date)
            issuer = self.cert.get_issuer().get_components()
            self.issuer = output = {item[0].decode(): item[1].decode() for item in issuer}
            subject = self.cert.get_subject().get_components()
            self.subject = output = {item[0].decode(): item[1].decode() for item in subject}
            print(self.issuer)
            print(self.subject)
        except:
            self.cert = None

    def add_url(self, Url):
        self.urllist.append(Url)

    def domain_info(self):
        try:
            self.whois = pythonwhois.get_whois(self.domain)
            print(self.whois)
            if "whois_server" not in self.whois:
                self.whois['whois_server'] = "No information available"
            if "emails" not in self.whois:
                self.whois['emails'] = ["No emails available"]
        except Exception as e:
            print("Error occured at DomainClass: " + str(e))


class BaseDomain(UrlDomain):

    def __init__(self, domainstr):
        super().__init__(domainstr, url=None)
        self.domain_info()

# UrlDomain("google.com", "https://google.com")