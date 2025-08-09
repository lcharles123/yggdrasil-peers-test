#!/usr/local/env python3

from parse_peers import main
import sys, asyncio


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"""
Usage: python3 {sys.argv[0]} <option>
        
\tOPTIONS:
\targ           If arg = 'key', print a list with key, if any, to be placed in /etc/yggdrasil/yggdrasil.conf file.
\t              If arg = 'any_string', print a table. Ping_latency = -1 means icmp requests did not get replied.""")
        print()
        sys.exit(0)
    asyncio.run(main(sys.argv[1]))
