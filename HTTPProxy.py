# PA1-Final
# Ro Erb
# CS 4480
# February 11, 2020

import sys
import socket
import select
import urlparse
import datetime
import threading
import requests
import hashlib
from optparse import OptionParser


def main():
    """
    main creates the proxySocket and begins listening for incoming
    requests. Once a client has arrived, it is accepted, and a
    thread created to handle the client request. If a
    KeyboardInterrupt happens, the proxy closes.
    """

    proxyPort = 2100
    proxyAddress = 'localhost'

    parser = OptionParser()
    parser.add_option("-k", dest="apiKey", type="string")
    (options, args) = parser.parse_args()
    apiKey = options.apiKey

    # Establish socket connection
    try:
        proxySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print "Client socket successfully created: ",  proxySocket.fileno()
    except socket.error as error:
        print "Client socket creation failed with error: ", error
        sys.exit(1)

    proxySocket.bind((proxyAddress, proxyPort))
    print 'Bound to: ', proxySocket.getsockname()

    proxySocket.listen(5)
    input = [proxySocket]

    # If the escape command ctrl + C is used, end the connection and exit
    try:
        while 1:
            inputready, outputready, exceptready = select.select(input, [], [])

            for s in inputready:
                # Client has arrived, accept, and create thread
                if s == proxySocket:
                    print 'Handle proxy socket'
                    clientSocket, addr = proxySocket.accept()
                    print 'Accepted connection from: ', addr

                    clientThread = threading.Thread(
                        target=processClientRequest, args=(clientSocket, addr, apiKey))
                    clientThread.setDaemon(True)
                    clientThread.start()

    except KeyboardInterrupt:
        print 'Closing proxy server.'
        sys.exit(1)


def errorMessage(errorCode):
    """
    errorMessage is given the specified errorCode and builds a
    an error message to be sent back to the client.
    """

    error = "HTTP/1.0 %s\r\n" % (errorCode)
    error += "Date: %s\r\n" % (
        datetime.datetime.now().strftime("%a, %d %b %Y %H:%M:%S"))
    error += "Connection: close\r\n"
    error += "\r\n"
    return error


def processClientRequest(clientSocket, addr, apiKey):
    """
    processClientRequest is given the clientSocket and receives
    the requested message. A connection to the destination server
    is established if no errors were found in the message. The
    serverResponse is forwared to the client and all connections
    are closed.
    """

    requestMessage = clientSocket.recv(1024)
    print 'Reading data from: ', clientSocket.getpeername()

    # If the requestMessage is empty, return a 400 Bad Request response
    if not requestMessage.rstrip():
        print 'Parsed incorrectly'
        clientSocket.send(errorMessage('400 Bad Request'))
        print 'Closing remote server socket', serverSocket.getpeername()
        clientSocket.close()

        print '\nWaiting for connection\n'
        return None

    requestLine = requestMessage.split('\n')[0].split(' ')

    # If the request line is not formatted properly, return a 400 Bad
    # Request response
    if len(requestLine) != 3:
        print 'Parsed incorrectly'
        clientSocket.send(errorMessage('400 Bad Request'))
        clientSocket.close()

        print '\nWaiting for connection\n'
        return None

    url = urlparse.urlsplit(requestLine[1])

    # If the method requested is not GET, return a 501 Not Implemented
    # response
    if requestLine[0] != 'GET':
        print 'Incorrect method'
        clientSocket.send(errorMessage('501 Not Implemented'))
        clientSocket.close()

        print '\nWaiting for connection\n'
        return None

    # Else if the URL is incorrectly formatted, return a 400 Bad Request response
    elif not (url.scheme and url.netloc):
        print 'URL incorrectly formatted'
        clientSocket.send(errorMessage('400 Bad Request'))
        clientSocket.close()

        print '\nWaiting for connection\n'
        return None

    # Else if the HTTP/1.0 is not requested, return a 400 Bad Request response
    elif requestLine[2].rstrip() != 'HTTP/1.0':
        print 'Incorrect HTTP version'
        clientSocket.send(errorMessage('400 Bad Request'))
        clientSocket.close()

        print '\nWaiting for connection\n'
        return None

    # Build the request message from the client to the server
    serverRequest = "%s %s %s\r\n" % (
        requestLine[0], url.path, requestLine[2].rstrip())
    serverRequest += "Host: %s\r\n" % (url.hostname)
    serverRequest += "Connection: close\r\n"
    serverRequest += "\r\n"

    if not url.port:
        port = 80
    else:
        port = int(url.port)

    serverSocket = ""
    try:
        serverSocket = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM)
        serverSocket.connect((url.hostname, port))
    except socket.error as error:
        print "Server socket creation failed with error: ", error
        clientSocket.send(errorMessage('502 Bad Gateway'))
        clientSocket.close()

        print '\nWaiting for connection\n'
        return None

    serverSocket.send(serverRequest)

    print 'Connecting to remote server: ', serverSocket.getpeername()

    checkResponse = ""
    while 1:
        serverResponse = serverSocket.recv(1024)
        if not serverResponse:
            break

        checkResponse += serverResponse

    if checkResponse:

        # Split the received response at new line "\r\n\r\n"
        splitResponse = checkResponse.split("\r\n\r\n", 1)

        # Convert the serverResponse data (not including headers)
        # to MD5
        encMessage = hashlib.md5(splitResponse[1]).hexdigest()

        # Set up VirusTotal connection
        VTurl = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {
            'apikey': apiKey, 'resource': encMessage}
        response = requests.get(VTurl, params=params)
        jsonResponse = response.json()

        # If the response from VirusTotal is empty, return 5xx Server Error
        if not jsonResponse:
            clientSocket.send(errorMessage('5xx Server Error'))

        # Else if the response from VirusTotal is not 1, the value sent
        # to VirusTotal was not found in their database, assume it is
        # "clean" and send server response to the client
        elif jsonResponse['response_code'] != 1:
            clientSocket.send(checkResponse)

        # Else the requested value was found in VirusTotal's database
        else:

            # If no positive results were found, send server response
            # back to the client
            if jsonResponse['positives'] == 0:
                clientSocket.send(checkResponse)

            # Else malware was found, send server response header
            # and a content blocked message back to the client
            else:
                malwareResponse = splitResponse[0] + "\r\n\r\n"
                malwareResponse += "content blocked" + "\r\n\r\n"
                clientSocket.send(malwareResponse)

    print 'Closing remote server socket', serverSocket.getpeername()
    serverSocket.close()
    clientSocket.close()

    print '\nWaiting for connection\n'
    return None


if __name__ == '__main__':
    main()
