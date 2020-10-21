#!/usr/bin/env python

from argparse import ArgumentParser
import requests
from NagiosResponse import NagiosResponse

def main():
    
    parser = ArgumentParser(description="Check the health status of the push server through AMS")
    parser.add_argument('-H', dest='host', type=str, required=True, help='AMS host')
    parser.add_argument('--port', dest='port', default=443, type=int, help='AMS port')
    parser.add_argument('--token', dest='token', type=str, required=True, help='AMS admin viewer token')
    parser.add_argument("--verify", dest='verify', help="SSL verification for requests", action="store_true")
    args = parser.parse_args()
    
    nagios = NagiosResponse("SERVING")

    health_url = 'https://{0}:{1}/v1/status?key={2}&details=true'.format(args.host, args.port, args.token)

    try:
        health_req = requests.get(url=health_url, timeout=30, verify=args.verify)
        
        if health_req.status_code == 200:
            if "push_servers" in health_req.json():
                ps = health_req.json()["push_servers"][0]
                if ps["status"] == "SERVING":
                    print(nagios.getMsg())
                    raise SystemExit(nagios.getCode())
                else:
                    nagios_report(nagios, "critical", ps["status"])
            else:
                nagios_report(nagios, "critical", "No push server available in response")
        else:
            nagios_report(nagios, "critical", health_req.text)
    except Exception as e:
        nagios_report(nagios, "critical", e.msg) 

def nagios_report(nagios, status, msg):
    nagios_method = getattr(nagios, "write{0}Message".format(status.capitalize()))
    nagios_method(msg)
    nagios_status = getattr(nagios, status.upper())
    nagios.setCode(nagios_status)
    if status == 'critical':
        print(nagios.getMsg())
        raise SystemExit(nagios.getCode())

if __name__ == '__main__':
    main()
