#!/usr/bin/python
# -*- coding: utf-8 -*-
import requests
import time
import sys
import sqlite3
from bs4 import BeautifulSoup
import hashlib
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class storage:
    def __init__(self,path="./alerts_wordpress.db"):
        self.path=path
        self.con=self.__conect()
        self.cur=self.__cursor()
        self.__createDB()

    def __conect(self):
        try:
            con = sqlite3.connect(self.path)
            return con
        except:
            print("Error when try connect with db")
            sys.exit(1)

    def __cursor(self):
        try:
            return self.con.cursor()
        except:
            print("Error generating the cursor")
            sys.exit(1)

    def __createDB(self):
        sent="""CREATE TABLE IF NOT EXISTS vulns(vdate TEXT, description TEXT, source TEXT, rule TEXT, vmd5 TEXT)"""
        self.cur.execute(sent)

    def insertVulns(self,vulns):
        for vuln in vulns:
            if self.__checkIfExistAVuln(vuln) is False:
                sent='''insert into vulns values ("{0}","{1}","{2}","{3}","{4}")'''.format(vuln.getDate(), vuln.getDesc(), vuln.getSrc(), "NULL", vuln.getMD5())
                self.cur.execute(sent)
                print("[!]Inserting...: " + vuln.getDesc())
                self.con.commit()

    def __checkIfExistAVuln(self,vuln):
        sent="""select count(*) from vulns where vmd5='{0}'""".format(vuln.getMD5())
        self.cur.execute(sent)
        resp = self.cur.fetchone()
        if int(resp[0]) > 0:
            return True
        else:
            return False
    def doInsert(self):
        pass

class vuln:
    def __init__(self,description,source,date):
        self.desc=description
        self.src=source
        self.date=date
        self.md5=self.__generateMD5(self.desc)

    def __generateMD5(self,string):
        m=hashlib.md5()
        m.update(str(string).encode('utf-8'))
        return m.hexdigest()
    def getDesc(self):
        return self.desc
    def getSrc(self):
        return self.src
    def getDate(self):
        return self.date
    def getMD5(self):
        return self.md5

class src:
    def __init__(self,url,date=time.strftime("%Y-%m-%d")):
        self.url=url
        self.vulns=[]
        self.date=date

    def getParsedHTML(self):
        requests.packages.urllib3.disable_warnings()
        html = requests.get(self.url,verify=False,headers={"User-Agent":"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:54.0) Gecko/20100101 Firefox/54.0"}).text
        phtml=BeautifulSoup(html,"html.parser")
        return phtml

    def addVuln(self,desc,src):
        v=vuln(description=desc,source=src, date=self.date)
        self.vulns.append(v)

    def getVulns(self):
        self.searchVulns()
        return self.vulns

class wpvulndb(src):
    def searchVulns(self):
        for i in self.getParsedHTML().body.find_all("tr"):
            vdate = str(i).split("\n")[1].split(">")[1].split("<")[0]
            desc = str(i).split("\n")[2].split(">")[2].split("<")[0]
            if str(self.date) == str(vdate):
                self.addVuln(desc, self.url)

class exploitdb(src):
    def searchVulns(self):
        for i in self.getParsedHTML().body.find_all("tr"):
            pohtml=BeautifulSoup(str(i),"html.parser")
            vdate = pohtml.find_all(class_="date")[0].get_text()
            desc = pohtml.find_all(class_="description")[0].get_text()[:-1][1:]
            if str(self.date) == str(vdate) and (("wordpress" in str(desc).lower()) or ("joomla" in str(desc).lower())):
                self.addVuln(desc, self.url)
def main():
    db=storage()
    ss=[wpvulndb("https://wpvulndb.com/"), exploitdb("https://www.exploit-db.com/webapps/")]
    for source in ss:
        vulns=source.getVulns()
        db.insertVulns(vulns)

if __name__=="__main__":
    main()
