#!/usr/bin/env python3

import argparse
import base64
import sys
import urllib.parse


parser = argparse.ArgumentParser(description="Encode or decode Base64.")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-d", "--decode", metavar="DATA", help="Decode Base64")
group.add_argument(
    "-e",
    "--encode",
    metavar="DATA",
    help="Encode text, or use @FILE to encode binary file contents"
)
args = parser.parse_args()

if args.decode is not None:
    data = args.decode
    if "%" in data:
        data = urllib.parse.unquote(data)

    try:
        decoded = base64.b64decode(data, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        parser.error(f"invalid Base64: {error}")

    sys.stdout.buffer.write(decoded)

else:
    if args.encode.startswith("@"):
        try:
            with open(args.encode[1:], 'rb') as file:
                raw = file.read()
        except OSError as error:
            parser.error(str(error))
    else:
        raw = args.encode.encode()

    encoded = base64.b64encode(raw).decode('ascii')
    url_encoded = urllib.parse.quote(encoded, safe="")

    print(encoded)

    if url_encoded != encoded:
        print(url_encoded)
