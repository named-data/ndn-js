#!/usr/bin/env python

# This "script Native Messaging application listens on the NDN multicast address
# for Native Messaging packets and sends them to stdout. It also takes any
# Native Messaging packets from stdin and sends to the NDN multicast address.
# A "Native Messaging packet" has a 4-byte length header followed by the bytes
# of a serialized JSON object.

import sys
import struct
import socket
import select
import time
import threading
from io import BytesIO

class SocketPoller(object):
    """
    Create a new SocketPoller and register with the given sock

    :param socket sock: The socket to register with.
    """
    def __init__(self, sock):
        self._socket = sock
        self._poll = None
        self._kqueue = None
        self._kevents = None

        if hasattr(select, "poll"):
            # Set up _poll.  (Ubuntu, etc.)
#pylint: disable=E1103
            self._poll = select.poll()
            self._poll.register(sock.fileno(), select.POLLIN)
#pylint: enable=E1103
        elif hasattr(select, "kqueue"):
            ## Set up _kqueue. (BSD and OS X)
            self._kqueue = select.kqueue()
            self._kevents = [select.kevent(
              sock.fileno(), filter = select.KQ_FILTER_READ,
              flags = select.KQ_EV_ADD | select.KQ_EV_ENABLE |
                      select.KQ_EV_CLEAR)]
        elif not hasattr(select, "select"):
            # Most Python implementations have this fallback, so we
            #   don't expect this error.
            raise RuntimeError("Cannot find a polling utility for sockets")

    def isReady(self):
        """
        Check if the socket given to the constructor has data to receive.

        :return: True if there is data ready to receive, otherwise False.
        :rtype: bool
        """
        if self._poll != None:
            isReady = False
            # Set timeout to 0 for an immediate check.
            for (fd, pollResult) in self._poll.poll(0):
#pylint: disable=E1103
                if pollResult > 0 and pollResult & select.POLLIN != 0:
                    return True
#pylint: enable=E1103

            # There is no data waiting.
            return False
        elif self._kqueue != None:
            # Set timeout to 0 for an immediate check.
            return len(self._kqueue.control(self._kevents, 1, 0)) != 0
        else:
            # Use the select fallback which is less efficient.
            # Set timeout to 0 for an immediate check.
            isReady, _, _ = select.select([self._socket], [], [], 0)
            return len(isReady) != 0

NDN_MULTICAST_IP = '224.0.23.170'
MY_IP = socket.gethostbyname(socket.gethostname())
NDN_MULTICAST_PORT = 56363

# See the multicast tutorial at https://pymotw.com/2/socket/multicast.html .
inSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
inSocket.bind(('', NDN_MULTICAST_PORT))
inSocketPoller = SocketPoller(inSocket)
# Tell the operating system to add the socket to the multicast group on all
# interfaces.
inSocket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                    socket.inet_aton(MY_IP))
inSocket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                    socket.inet_aton(NDN_MULTICAST_IP)
                    + socket.inet_aton(MY_IP))

outSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
outSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
outSocket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                     socket.inet_aton(MY_IP))

# Don't send packets in a loop.
outSocket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
# Set a timeout so the socket does not block indefinitely when trying to receive
# data.
outSocket.settimeout(0.2)
# Set the time-to-live for messages to 1 so they do not go past the local
# network segment.
outSocket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack('b', 1))

buffer = bytearray(10000)

# Expect: {"type":"Buffer","data":[1,2,3]}
JSON_PREFIX = '{"type":"Buffer","data":['
JSON_SUFFIX = ']}'

def printOneBroadcasted():
    while True:
        if not inSocketPoller.isReady():
            # There is no data waiting.
            break

        nBytesRead, _ = inSocket.recvfrom_into(buffer)
        if nBytesRead <= 0:
            # Since we checked for data ready, we don't expect this.
            break

        # TODO: Use an ElementReader. For now assume one packet is one TLV element.
        elementLength = nBytesRead

        # Convert element to a JSON Buffer.
        jsonIO = BytesIO()
        jsonIO.write(JSON_PREFIX)

        for i in range(elementLength):
            if i != 0:
                jsonIO.write(',')
            jsonIO.write(str(buffer[i]))

        jsonIO.write(JSON_SUFFIX)
        json = jsonIO.getvalue()

        sys.stdout.write(struct.pack('@I', len(json)))
        sys.stdout.write(json)
        sys.stdout.flush()

printAllBroadcastedEnabled = True
def printAllBroadcasted():
    while printAllBroadcastedEnabled:
        printOneBroadcasted()
        # We need to sleep for a few milliseconds so we don't use 100% of the CPU.
        time.sleep(0.1)

    inSocket.close()

def asciiToChr(x):
    return chr(int(x))

def multicastAllStdin():
    # Loop until there is no more data in stdin.
    while True:
        # The Native Messaging packet starts with a 4-byte length
        rawLength = sys.stdin.read(4)
        if len(rawLength) == 0:
            # Input EOF. Finished.
            return

        jsonLength = struct.unpack('@I', rawLength)[0]
        json = sys.stdin.read(jsonLength)

        if (json.find(JSON_PREFIX) != 0 or
            json.find(JSON_SUFFIX) != len(json) - len(JSON_SUFFIX)):
            # This is not the JSON of a Buffer.
            continue

        # Set asciiElements to the Buffer data such as "1,2,3". Then split into
        # ascii elements, map them to raw chars and join them into a raw string.
        asciiArray = json[len(JSON_PREFIX) : -len(JSON_SUFFIX)]
        rawString = "".join(map(asciiToChr, asciiArray.split(',')))

        outSocket.sendto(rawString, (NDN_MULTICAST_IP, NDN_MULTICAST_PORT))

thread = threading.Thread(target=printAllBroadcasted)
thread.start()
multicastAllStdin()
printAllBroadcastedEnabled = False

outSocket.close()
