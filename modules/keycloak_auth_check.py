import argparse
import sys

import requests

from NagiosResponse import NagiosResponse


def main():
    parser = argparse.ArgumentParser(
        description='Nagios probe for Keycloak login'
    )
    parser.add_argument(
        "--token_endpoint", dest="endpoint", type=str, required=True,
        help="The token endpoint"
    )
    parser.add_argument(
        "--client_id", dest="client_id", type=str, required=True,
        help="The identifier of the client"
    )
    parser.add_argument(
        "--client_secret", dest="client_secret", type=str, required=True,
        help="The secret value of the client"
    )
    parser.add_argument(
        "-t", "--timeout", dest="timeout", type=int, default=60,
        help="timeout"
    )
    args = parser.parse_args()

    nagios = NagiosResponse("Access token fetched successfully.")

    try:
        response = requests.post(
            args.endpoint,
            auth=(args.client_id, args.client_secret),
            data={
                "client_id": args.client_id,
                "client_secret": args.client_secret,
                "grant_type": "client_credentials"
            },
            timeout=args.timeout
        )
        response.raise_for_status()

        access_token = response.json()["access_token"]
        assert access_token

        print nagios.getMsg()
        sys.exit(nagios.getCode())

    except (
        requests.exceptions.HTTPError,
        requests.exceptions.ConnectionError,
        requests.exceptions.RequestException,
        ValueError,
        KeyError,
        AssertionError
    ) as e:
        nagios.writeCriticalMessage(str(e))
        nagios.setCode(nagios.CRITICAL)
        print nagios.getMsg()
        sys.exit(nagios.getCode())


if __name__ == '__main__':
    main()
