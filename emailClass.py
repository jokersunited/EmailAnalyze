from email.parser import HeaderParser
from email.header import decode_header
import email.utils
import email
from email import policy
from flask import Markup
from tldextract import extract
import pickle
import base64

import homoglyphs as hg

import re
import pandas as pd
import copy

from ipClass import *
from domainClass import *

from nltk.stem.porter import PorterStemmer
from nltk.corpus import stopwords
from sklearn.ensemble import RandomForestClassifier
from ipaddress import ip_network, ip_address

remove_chars = ["<", ">", ";", ":", "\n", "]", "["]
range1 = list(range(ord('a'), ord('z')))
range2 = list(range(ord('A'), ord('Z')))
range3 = [ord('-'), ord('\''), ord("©")]

#Read the list of words to be used to process and match in email body
wordFrame = pd.read_csv("phishwords.csv", encoding="ISO-8859-1", engine='python')
porter = PorterStemmer()

#Check if string is base64
def isBase64(sb):
        try:
                if isinstance(sb, str):
                        # If there's any unicode here, an exception will be thrown and the function will return false
                        sb_bytes = bytes(sb, 'ascii')
                elif isinstance(sb, bytes):
                        sb_bytes = sb
                else:
                        raise ValueError("Argument must be string or bytes")
                return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
        except Exception:
                return False

#Remove certain chars from a specific string
def replace_chars(string):
    s = string
    for char in remove_chars:
        s = s.replace(char, "")
    return s

#Extracts substrings using regular expressions
def re_extractor(string, strtype, regexp=None):
    if strtype == "ip":
        regexp = "(?:^|\\b(?<!\\.))(?:1?\\d\\d?|2[0-4]\\d|25[0-5])(?:\\.(?:1?\\d\\d?|2[0-4]\\d|25[0-5])){3}(?=$|[^\\w.])"

    end_str = ""
    result = re.findall(regexp, string)
    if not result:
        return end_str
    else:
        return result

#Declare the ASCII range that is considered to not be homoglyphs
ascii_range = list(range(0, 128))
ascii_range.append(ord("©"))

#Check percentage of text in the body that are homoglyphs
def check_homo_percentage(body):
    homo_counter = 0
    for letter in body:
        if ord(letter) not in ascii_range:
            homo_counter += 1
        else:
            continue
    return homo_counter/len(body)

#Email class that stores all information for each email
class EmailParser:

    def __init__(self, emailfile):

        #List of relay domains & IPs
        self.recv_ips = []
        #Header and Body content of the email
        self.headers = ""
        self.body = ""
        self.text = ""
        #Email inforation of sender
        self.sender_email = ""
        self.sender_name = ""
        self.return_path = ""
        self.receiver = ""

        #Email information of body
        self.subject = ""
        self.date = ""
        self.urls = []
        self.domain_dict = {}
        self.ip_links = 0
        self.homo = 0.0
        self.word_dict = {}
        self.row_detail = []

        self.urlextract = False

        #Tests
        self.checks = {"Email Spoofing": [], "Body Content": []}
        self.phish = False
        self.black = []
        self.cat = []

        #Get header and body informations
        data = emailfile
        parser = HeaderParser()
        self.headers = parser.parsestr(data)
        self.body = email.message_from_string(data, policy=policy.default)
        self.text = self.get_text()

        #Get source and destination and reply to addresses
        if self.headers['Delivered-To'] is not None:
            self.receiver = replace_chars(self.headers['Delivered-To'])
        elif self.body['to'] is not None:
            self.receiver = replace_chars(self.body['to'])
        if self.body['Return-Path'] is not None:
            self.return_path = replace_chars(self.body['Return-Path'])
        else:
            self.return_path = "Unavailable"

        sender_from = self.body["from"]
        if "<" in sender_from or ">" in sender_from:
            self.sender_email = sender_from.split("<")[1].split(">")[0]
            if "\"" not in sender_from:
                self.sender_name = sender_from.split(" ")[0]
            else:
                self.sender_name = sender_from.split("\"")[1]

        else:
            self.sender_email = sender_from

        #Get email subject
        self.subject = self.body["subject"]
        if self.subject[:8].lower() == "=?utf-8?":
            self.subject = decode_header(self.subject)[0][0].decode("utf-8")


        #Get email date
        raw_date = self.body["date"]
        self.date = email.utils.parsedate_to_datetime(raw_date)

        #Parse header to get IP relays
        self.get_relays()


        #Checks
        self.check_auth()
        self.domain_align()
        self.ip_link_check()
        self.homo_check()
        self.check_text(wordFrame)
        self.check_blacklist()
        # self.get_df_row()

        print("=== " + self.subject + " INFO ===")
        print(self.checks)
        print(self.clean_text())

#==========================CLASS FUNCTIONS=================================
    def get_text(self):
        if self.body.is_multipart():
            full_body = ""
            for part in self.body.get_payload():
                if "text" in part.get_content_type():
                    try:
                        decoded = base64.b64decode(part.get_payload()).decode()
                    except:
                        decoded = part.get_payload()
                    full_body += decoded
        else:
            try:
                full_body = base64.b64decode(self.body.get_payload()).decode()
            except:
                full_body = self.body.get_payload()

        return full_body

    #Create a string to display the checks for IP address links
    def ip_link_check(self):
        self.checks['Body Content'].append(["IP ADDRESS LINKS", "", "YES" if self.ip_links != 0 else "NO"])


    #Check for domain alignment between from field and source address in header
    def domain_align(self):
        if self.sender_email == "Unavailable" or self.return_path == "Unavailable":
            self.checks['Email Spoofing'].append(["DOMAIN ALGINMENT","", "FAIL"])
            return

        base_domain_extractor = r'@(?:.*\.|)(.+?\.)([^\.]+?)$'

        sender_domain = re.findall(base_domain_extractor, self.sender_email)[0]
        return_domain = re.findall(base_domain_extractor, self.return_path)[0]
        
        if sender_domain != return_domain:
            self.checks['Email Spoofing'].append(["DOMAIN ALGINMENT","", "FAIL"])
        else:
            self.checks['Email Spoofing'].append(["DOMAIN ALIGNMENT","", "PASS"])

    #Look for DKIM SPF and DMARC records from authentication headers
    def check_auth(self):
        re_filter = r'(?:dkim=.+? |spf=.+? |dmarc=.+? ).+?(?:;|$)'

        para_filter = r'(.+?)='
        result_filter = r'(?:dkim=|spf=|dmarc=)(.+?)(?:;| |\()'

        dkim_domain_filter = r'(?:header\.i=(|@)|header\.d=)(.+?)(?:;| |$)'
        spf_domain_filter = r'(?:smtp.helo|smtp.mailfrom)=(.+?)(?:;|$)'

        
        if self.headers['Authentication-Results'] is not None:
            auths = re.findall(re_filter, self.headers['Authentication-Results'])
        elif self.headers['ARC-Authentication-Results'] is not None:
            auths = re.findall(re_filter, self.headers['Arc-Authentication-Results'])
        else:
            auths = []
        for auth in auths:
            auth_type = re.findall(para_filter, auth)[0]
            auth_result = re.findall(result_filter, auth)[0]
            try:
                if auth_type == 'spf':
                    auth_descrip = re.findall(spf_domain_filter, auth)[0]

                elif auth_type == 'dkim':
                    auth_descrip = re.findall(dkim_domain_filter, auth)[0][1].split("=")[-1]

                else:
                    auth_descrip = ""
            except:
                auth_descrip = ""
            self.checks['Email Spoofing'].append([auth_type.upper(), auth_descrip, auth_result.upper()])
        spf_check = False
        dkim_check = False
        dmarc_check = False
        for check in self.checks['Email Spoofing']:
            if check[0] == 'SPF':
                spf_check = True
            if check[0] == 'DKIM':
                dkim_check = True
            if check[0] == 'DMARC':
                dmarc_check = True
        if spf_check is not True:
            self.checks['Email Spoofing'].append(["SPF", "", "-"])
        if dkim_check is not True:
            self.checks['Email Spoofing'].append(["DKIM", "", "-"])
        if dmarc_check is not True:
            self.checks['Email Spoofing'].append(["DMARC", "", "-"])

        
    #Obtain IP and domain information for all SMTP relays
    def get_relays(self):
        for header, value in self.headers.items():
            if header == "Received":
                ip_addr = re_extractor(value.split("by")[0], "ip")
                if ip_addr == "":
                    ip_obj = None
                    continue
                else:
                    ip_obj = IP(ip_addr[len(ip_addr)-1])
                domain = replace_chars(value.split(" ")[1])
                self.recv_ips.append([domain, ip_obj])
            if header == "Received-SPF":
                split_spf = value.split(" ")
                for item in split_spf:
                    if "client-ip" in item:
                        ip_addr = replace_chars(item.split("=")[1])
                        if ip_addr == "":
                            ip_obj = None
                        else:
                            ip_obj = IP(ip_addr)
                        try:
                            if self.recv_ips[-1][1].ip == ip_addr:
                                continue
                        except:
                            pass
                        ip_obj = IP(ip_addr)
                        self.recv_ips.append(["SPF CHECK", ip_obj])
            if header.lower() == "x-originating-ip":
                if "[" not in value:
                    ip_obj = IP(value)
                else:
                    ip_obj = IP(value[1:-1])
                self.recv_ips.append(["X-ORIGINATING-IP", ip_obj])
        return

    #Get a printable date to display as a string from datetime
    def get_printable_date(self):
        return self.date.strftime('%y/%m/%d %H:%M')

    #Truncate string length of the subject to not over display in the UI
    def get_truncated_subject(self):
        end_string = ""
        if len(self.subject) > 60:
            cut_string = self.subject[:60].split(" ")[:-1]
            cut_string.append("...")
            for word in cut_string:
                end_string += word
                end_string += " "
        else:
            end_string = self.subject
        return end_string

    #Look through SMTP relay IPs to determine the source country
    def get_source(self):
        for ip_index in range(len(self.recv_ips), 0, -1):
            if self.recv_ips[ip_index-1][1] is None:
                continue
            elif not self.recv_ips[ip_index-1][1].queried:
                continue
            else:
                return self.recv_ips[ip_index-1][1].country

    #Get the HTML markup version of text
    def markup_html(self):
        return Markup(self.body.get_payload())

    #Extract URLs from the body of the email
    def get_urls(self):
        url_regex = r'(http:\/\/|https:\/\/)([a-zA-Z0-9](.+?[^=])*?)(?:>|"|$| |\n|\r)'
        
        if type(self.body.get_payload()) == list:
            raw_urls = re.findall(url_regex, str(self.body.get_payload()[-1]))
        else:
            raw_urls = re.findall(url_regex, str(self.body.get_payload()))
            
        urls = [(x[0]+x[1]).replace("\"", "").replace("=", "").replace(">", "").replace("\n", "").split(" ")[0] for x in raw_urls]
        self.urls = urls
    #Check the percentage of homoglyphs for the text body
    def homo_check(self):
        if type(self.body.get_payload()) == list:
            self.homo = check_homo_percentage(str(self.body.get_payload()[0]))
        else:
            self.homo = check_homo_percentage(str(self.body.get_payload()))
        self.checks['Body Content'].append(["HOMOGLYPH PERCENTAGE","", str("{:.2f}".format(self.homo*100))+"%"])

    #Check for IP addresses in URLs, seperate domains from subdomains and group URLs from similar domains together, get HTTPS cert info
    def unique_url_ips(self):

        ip_regex = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        domain_dict = {}
        for url in self.urls:
            try:
                domain_extractor = extract(url)
                if re.findall(ip_regex, domain_extractor.domain) != []:
                    self.ip_links += 1
                    if domain_extractor.domain in domain_dict.keys():
                        domain_dict[domain_extractor.domain][0].add_url(url)
                    else:
                        domain_dict.update({domain_extractor.domain : [UrlDomain(domain_extractor.domain, url), None]})
                else:
                    domain = ".".join(domain_extractor)
                    base_domain = domain_extractor.registered_domain

                    if base_domain in domain_dict.keys():
                        if domain in domain_dict[base_domain][1].keys():
                            domain_dict[base_domain][1][domain].add_url(url)
                        else:
                            domain_dict[base_domain][1].update({domain: UrlDomain(domain,url,)})
                    else:
                        domain_obj = UrlDomain(domain,url)
                        basedomain_obj = BaseDomain(base_domain)
                        domain_dict.update({base_domain : [basedomain_obj, {domain: domain_obj}]})
            except Exception as e:
                print("Error occured at unique url Ips: " + str(e))
        self.domain_dict = domain_dict
        print(self.domain_dict)

    #Clean text in body, convert homoglyphs, stem words to prepare for list comparison
    def clean_text(self):
        money_chars = ["$", "¥", "€", "£"]
        html_re = r'(<style.*>[^<]*<\/style>|<script>[^<]*<\/script>|<[^>]*>)'
        cleaner_re = r'(:|\(|\)|<|>|\?|\/|!|\.|,|=|\+|~|`|"|\'|\\|\n|\r|\t|[0-9]|nbsp)'

        word_list = []

        homoglyphs = hg.Homoglyphs(languages={'en'},
            strategy=hg.STRATEGY_LOAD,
            ascii_strategy=hg.STRATEGY_REMOVE,
            ascii_range= range1 + range2 + range3)

        if self.body.is_multipart():
            full_body = ""
            for part in self.body.get_payload():
                if "text" in part.get_content_type():
                    try:
                        decoded = base64.b64decode(part.get_payload()).decode()
                    except:
                        decoded = part.get_payload()
                    full_body += decoded
        else:
            try:
                full_body = base64.b64decode(self.body.get_payload()).decode()
            except:
                full_body = self.body.get_payload()

        body_text = re.sub(html_re, ' ', full_body)
        body_text = re.sub(cleaner_re, ' ', body_text)
        
        list_body = body_text.split(" ")


        for each_word in list_body:
            if each_word in money_chars:
                word_list.extend(each_word)
            if each_word == "" or len(each_word) > 15 or len(each_word) < 3:
                continue
            else:

                each_word = re.sub(cleaner_re, '', each_word)
                clean_word = (homoglyphs.to_ascii(each_word))

                if clean_word != []:
                    if clean_word[0].isupper():
                        clean_word = clean_word[0].lower()                
                    else:
                        clean_word = clean_word[-1].lower()
                    if not '-' in clean_word:
                        word_list.append(porter.stem(clean_word))
                    else:
                        clean_word = clean_word.split('-')
                        clean_word = [porter.stem(x) for x in clean_word]
                        word_list.extend(clean_word)
                else:
                    continue
        
        return word_list

    #Creates a count & percentage count of words on the cleaned body using a wordlist in csv (First row as category)
    def check_text(self, phishwords):
        word_list = self.clean_text()
        word_dict = {x : [0, []] for x in phishwords}

        for word in word_list:
            for column in phishwords:
                for long_bad_word in phishwords[column]:
                    if type(long_bad_word) is float:
                        continue
                    else:
                        bad_word = porter.stem(long_bad_word)
                        if word == bad_word:
                            word_dict[column][0] += 1
                            if bad_word in word_dict[column][1]:
                                continue
                            else:
                                word_dict[column][1].append(long_bad_word)

        # for key, value in word_dict.items():
        #     word_dict[key] = value/len(word_list)

        
        self.word_dict = copy.deepcopy(word_dict)
        self.word_dict.update({'length': len(word_list)+1})

        words = []
        word_count = 0

        for value in word_dict.values():
            words.extend(value[1])
            word_count += value[0]
        self.checks['Body Content'].append(["FLAGGED WORDS",words, str(word_count)+"/"+str(len(word_list))])
    #Get a row that contains information about all the tests (Can be used by random forest classifier)
    def get_df_row(self):
        columns = ['spf', 'dkim', 'dmarc', 'domain', 'iplink', 'homo', 'word_payment', 'word_account', 'word_postal', 'blacklisted_relay']

        goodspf = ['PASS']
        badspf = ['FAIL', 'SOFTFAIL']
        row = [0 for x in columns]
        for value in self.checks.values():
            for check in value:
                if check[0].lower() == 'spf':
                    if check[2] in goodspf:
                        row[0] = 1
                    elif check[2] in badspf:
                        row[0] = -1
                    else:
                        continue
                if check[0].lower() == 'dkim':
                    if check[2] in goodspf:
                        row[1] = 1
                    elif check[2] in badspf:
                        row[1] = -1
                    else:
                        continue
                if check[0].lower() == 'dmarc':
                    if check[2] in goodspf:
                        row[2] = 1
                    elif check[2] in badspf:
                        row[2] = -1
                    else:
                        continue
                if check[0].lower() == 'domain alignment':
                    if check[2] in goodspf:
                        row[3] = 1
                    elif check[2] in badspf:
                        row[3] = -1
                    else:
                        continue
                if check[0].lower() == 'ip address links':
                    if check[2] == 'NO':
                        row[4] = 1
                    else:
                        row[4] = 0
                if check[0].lower() == 'homoglyph percentage' and float(check[2][:-1]) > 0.01:
                    row[5] = 1
                else:
                    row[5] = 0
        row[6] = self.word_dict['money'][0] * (1 + self.word_dict['scare'][0] + self.word_dict['urgency'][0]) / \
                 self.word_dict['length']
        row[7] = self.word_dict['credentials'][0] * (1 + self.word_dict['scare'][0] + self.word_dict['urgency'][0]) / \
                 self.word_dict['length']
        row[8] = self.word_dict['postal'][0] * (1 + self.word_dict['scare'][0] + self.word_dict['urgency'][0]) / \
                 self.word_dict['length']
        row[9] = len(self.black)
        self.row_detail = row
        print(self.row_detail)
        print(columns)
        #Contains 1 extra column due to the malicious IP relay check
        pred_df = pd.DataFrame([self.row_detail], columns=columns)
        # if model.predict(pred_df)[0] == 1:
        #     self.phish = "FAIL"
        # else:
        #     self.phish = "PASS"
        self.phish = "PASS"

    #Checks against a list for malcious IP relays
    def check_blacklist(self):
        for ip in self.recv_ips:
            if ip[1] is None:
                continue
            elif ip[1].malicious:
                self.black.append(ip)
        self.checks['Email Spoofing'].append(["IP BLACKLIST", self.black, str(len(self.black))])

    #Classify the email based on header and content
    def classify(self):
        row = self.row_detail

    #Get a truncated base64 encoded string (used to create HTML modal IDs)
    def get_64(self, s):
        return base64.b64encode(s.encode("ascii")).decode("ascii")[:7]

    def get_month(self):
        pass

