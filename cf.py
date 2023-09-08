from google.cloud import bigquery
import os.path
import requests
import sys
import argparse
import datetime
import getopt
import time
client = bigquery.Client()
dataset_id = 'content_security_policy'
table_id = 'site_scan'
table_ref = client.dataset(dataset_id).table(table_id)
table = client.get_table(table_ref)

def log_site_cf(request):
    now = datetime.datetime.now()
    if request.args:  
        try:
            rows_to_insert = [
                {
                    "timestamp": int(time.time()),
                    "url": request.args.get('url'),
                    "status": request.args.get('status'),
                    "csp_found": request.args.get('csp_found'),
                    "csp_elements": request.args.get('csp_elements'),
                    "redirect": request.args.get('redirect'),
                    "redirect_url":request.args.get('redirect_url')
                }
            ]
            print(rows_to_insert)
            try:
                errors = client.insert_rows(table, rows_to_insert)
                print(errors)
                return '200 OK'
            except AssertionError as msg:
                return 'Error 500:'+msg
        except Exception as e:
            return '500 Internal Server Error: ' + e
    else:
        return '400 Bad Request'

def log_site_local(url,status,csp_found,csp_elements,redirect,redirect_url):
    now = datetime.datetime.now()
    try:
        rows_to_insert = [
            {
                "timestamp": int(time.time()),
                "url": url,
                "status": status,
                "csp_found": csp_found,
                "csp_elements": csp_elements,
                "redirect": redirect,
                "redirect_url":redirect_url,
                "scan_date": str(datetime.date.today())
            }
        ]
        print(rows_to_insert)
        try:
            errors = client.insert_rows(table, rows_to_insert)
            print(errors)
            return '200 OK'
        except AssertionError as msg:
            return 'Error 500:'+msg
    except Exception as e:
        return '500 Internal Server Error: ' + e

if __name__ == "__main__":
    if len(sys.argv) == 2:
        url = sys.argv[1]
        # usage cf.py https://yoursite.com
        res = requests.get(url)
        print(res.request)
        
        csp_found = 0
        if 'Content-Security-Policy-Report-Only' in res.headers:
            csp = res.headers['Content-Security-Policy-Report-Only']
        if 'Content-Security-Policy' in res.headers:
            csp = res.headers['Content-Security-Policy']
        if csp:
            csp_found=1
        if res.status_code in {'301','302','304'}:
            is_redirection = 1 
        else:
            is_redirection =0
        if is_redirection==1 and 'location' in res.headers:
            redirection_url = res.headers['location']
        else:
            redirection_url=''
        log_site_local(
            url,
            res.status_code,
            csp_found,
            csp,
            is_redirection,
            redirection_url
        )

    else:
        
        exit("No URL entered")
        