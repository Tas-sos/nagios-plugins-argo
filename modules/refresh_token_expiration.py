import argparse
import datetime
import signal
import sys

import jwt

from NagiosResponse import NagiosResponse

nagios = NagiosResponse("Refresh token valid.")


class TimeoutError(Exception):
    pass


class timeout:
    def __init__(self, seconds=1, error_message="Timeout"):
        self.seconds = seconds
        self.error_message = error_message

    def handle_timeout(self, signum, frame):
        raise TimeoutError(self.error_message)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, exc_type, exc_val, exc_tb):
        signal.alarm(0)


def validate_token(args):
    try:
        unix_time = jwt.decode(args.token, verify=False)["exp"]
        expiration_time = datetime.datetime.fromtimestamp(unix_time)
        timedelta = expiration_time - datetime.datetime.today()

        if 15 < timedelta.days < 30:
            nagios.writeWarningMessage(
                "Refresh token expiring in %d days!" % timedelta.days
            )
            nagios.setCode(nagios.WARNING)

        if timedelta.days < 15:
            nagios.writeCriticalMessage(
                "Refresh token expiring in %d days!" % timedelta.days
            )
            nagios.setCode(nagios.CRITICAL)

        print nagios.getMsg()

    except Exception as e:
        print "UNKNOWN - %s" % str(e)

        nagios.setCode(nagios.UNKNOWN)

    sys.exit(nagios.getCode())


def main():
    parser = argparse.ArgumentParser(
        description="Nagios probe for checking refresh token expiration"
    )
    parser.add_argument(
        "--token", dest="token", type=str, required=True, help="Refresh token"
    )
    parser.add_argument(
        "-t", "--timeout", dest="timeout", type=int, default=5, help="timeout"
    )
    args = parser.parse_args()

    with timeout(seconds=args.timeout):
        validate_token(args)


if __name__ == "__main__":
    main()
