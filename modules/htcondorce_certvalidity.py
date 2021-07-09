import argparse
import datetime
import os
import sys

import OpenSSL
import htcondor
import pytz
from dateutil.parser import parse

from NagiosResponse import NagiosResponse
from refresh_token_expiration import timeout

nagios = NagiosResponse("HTCondorCE certificate valid.")


def validate_certificate(args):
    # Setting X509_USER_PROXY environmental variable
    os.environ["X509_USER_PROXY"] = args.user_proxy

    try:
        ad = htcondor.Collector("%s:9619" % args.hostname).locate(
            htcondor.DaemonTypes.Schedd, args.hostname
        )
        cert = htcondor.SecMan().ping(ad, "READ")["ServerPublicCert"]
        x509 = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert
        )
        expiration_date = parse(x509.get_notAfter())
        timedelta = expiration_date - datetime.datetime.now(tz=pytz.utc)

        if 15 < timedelta.days < 30:
            nagios.writeWarningMessage(
                "HTCondorCE certificate expiring in %d days!" % timedelta.days
            )
            nagios.setCode(nagios.WARNING)

        if timedelta.days < 15:
            nagios.writeCriticalMessage(
                "HTCondorCE certificate expiring in %d days!" % timedelta.days
            )
            nagios.setCode(nagios.CRITICAL)

        print nagios.getMsg()

    except htcondor.HTCondorException as e:
        print "UNKNOWN - Unable to fetch certificate: %s" % str(e)
        nagios.setCode(nagios.UNKNOWN)

    except Exception as e:
        print 'UNKNOWN - %s' % str(e)
        nagios.setCode(nagios.UNKNOWN)

    sys.exit(nagios.getCode())


def main():
    parser = argparse.ArgumentParser(
        description="Nagios probe for checking HTCondorCE certificate validity"
    )
    parser.add_argument(
        "--user_proxy", dest="user_proxy", type=str, required=True,
        help="path to X509 user proxy"
    )
    parser.add_argument(
        "-H", "--hostname", dest="hostname", type=str, required=True,
        help="hostname"
    )
    parser.add_argument(
        "-t", "--timeout", dest="timeout", type=int, default=60, help="timeout"
    )
    args = parser.parse_args()

    with timeout(seconds=args.timeout):
        validate_certificate(args)


if __name__ == "__main__":
    main()
