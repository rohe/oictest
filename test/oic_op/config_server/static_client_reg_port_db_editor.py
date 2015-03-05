import argparse
from issuer_port_database import MySqllite3Dict

__author__ = 'danielevertsson'

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-lp', dest='port_list', action='store_true',
                        help="list all ports")
    parser.add_argument('-l', dest='complete_database', action='store_true',
                        help="list complete database")
    parser.add_argument('-r', dest='port_to_remove',
                        help="Remove port")
    parser.add_argument(dest="database")
    args = parser.parse_args()

    cdb = MySqllite3Dict(args.database)

    if args.port_list:
        print cdb.keys()

    if args.complete_database:
        print "Port   Issuer"
        print "****   ******"

        for port in cdb.keys():
            issuer = cdb[port]
            print str(port) + "   " + str(issuer)

    if args.port_to_remove:
        port = int(args.port_to_remove)
        if port in cdb:
            del cdb[port]
            print "Removed port: " + str(port) + " from database!"
            print cdb.keys()

