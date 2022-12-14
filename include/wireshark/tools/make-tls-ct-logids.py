#!/usr/bin/env python3
# Generate the array of Certificate Transparency Log ID to description mappings
# for the TLS dissector.
#
# To update the TLS dissector source file, run this from the source directory:
#
#   python3 tools/make-tls-ct-logids.py --update
#

import argparse
from base64 import b64decode, b64encode
import itertools
import requests
from hashlib import sha256


# Begin of comment, followed by the actual array definition
HEADER = "/* Generated by tools/make-tls-ct-logids.py\n"
# See also https://www.certificate-transparency.org/known-logs
CT_JSON_URL = 'https://www.gstatic.com/ct/log_list/v3/all_logs_list.json'
# File to be patched
SOURCE_FILE = "epan/dissectors/packet-tls-utils.c"

# Maximum elements per line in the value array. 11 is chosen because it results
# in output consistent with clang-format.
BYTES_PER_LINE = 11


def escape_c(s):
    return s.replace('\\', '\\\\').replace('"', '\\"')


def byteshex(b):
    return " ".join("0x%02x," % b for b in bytearray(b))


def process_json(obj, lastmod):
    logs = list(itertools.chain(*[op['logs'] for op in obj['operators']]))
    lines = HEADER
    lines += " * Last-Modified %s, %s entries. */\n" % (lastmod, len(logs))
    lines += "static const bytes_string ct_logids[] = {\n"
    for entry in logs:
        desc = entry["description"]
        pubkey_der = b64decode(entry["key"])
        key_id = sha256(pubkey_der).digest()
        lines += '    { (const guint8[]){\n'
        for offset in range(0, len(key_id), BYTES_PER_LINE):
            lines += '          %s\n' % \
                byteshex(key_id[offset:offset+BYTES_PER_LINE])
        lines += '      },\n'
        lines += '      %d, "%s" },\n' % (len(key_id), escape_c(desc))
    lines += "    { NULL, 0, NULL }\n"
    lines += "};\n"
    return lines


def parse_source():
    """
    Reads the source file and tries to split it in the parts before, inside and
    after the block.
    """
    begin, block, end = '', '', ''
    # Stages: 1 (before block), 2 (in block, skip), 3 (after block)
    stage = 1
    with open(SOURCE_FILE) as f:
        for line in f:
            if line == HEADER:
                stage = 2   # Begin of block
            if stage == 1:
                begin += line
            elif stage == 2:
                block += line
                if line.startswith('}'):
                    stage = 3   # End of block reached
            elif stage == 3:
                end += line
    if stage != 3:
        raise RuntimeError("Could not parse file (in stage %d)" % stage)
    return begin, block, end


parser = argparse.ArgumentParser()
parser.add_argument("--update", action="store_true",
                    help="Update %s as needed instead of writing to stdout" % SOURCE_FILE)


def main():
    args = parser.parse_args()
    r = requests.get(CT_JSON_URL)
    code = process_json(r.json(), lastmod=r.headers['Last-Modified'])

    if args.update:
        begin, block, end = parse_source()
        if block == code:
            print("File is up-to-date")
        else:
            with open(SOURCE_FILE, "w") as f:
                f.write(begin)
                f.write(code)
                f.write(end)
            print("Updated %s" % SOURCE_FILE)
    else:
        print(code)


if __name__ == '__main__':
    main()
