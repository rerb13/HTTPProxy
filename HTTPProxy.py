# PA1-Final
# Ro Erb
# CS 4480
# February 11, 2020

import sys
import os
import socket
import select
from urllib.parse import urlparse
import urllib.request
import urllib.error
import datetime
import threading
from aiohttp import request
import requests
import hashlib
import json
import logging
import traceback
# import vt
from optparse import OptionParser
from dotenv import load_dotenv

load_dotenv()

# telnet localhost 2100
# GET http://www.google.com/ HTTP/1.0
# GET http://www.cs.utah.edu/~kobus/simple.html HTTP/1.0

def main():
    """
    main creates the proxySocket and begins listening for incoming
    requests. Once a client has arrived, it is accepted, and a
    thread created to handle the client request. If a
    KeyboardInterrupt happens, the proxy closes.
    """

    proxyPort = 2100
    proxyAddress = "localhost"

    # parser = OptionParser()
    # parser.add_option("-k", dest="apiKey", type="string")
    # (options, args) = parser.parse_args()
    # apiKey = options.apiKey

    apiKey = os.getenv("VT_API_KEY")

    # Establish socket connection
    try:
        proxySocket = socket.socket(
                family=socket.AF_INET, 
                type=socket.SOCK_STREAM, 
                proto=socket.IPPROTO_TCP,
            )

        print ("Client socket successfully created: "),  proxySocket.fileno()
    except KeyboardInterrupt:
        print("Shutting down server")
        sys.exit()
    except socket.error as error:
        print ("Client socket creation failed with error: "), error
        sys.exit()

    proxySocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxySocket.bind((proxyAddress, proxyPort))
    print ("Bound to: ", proxySocket.getsockname())

    # 10 is the backlog size or the size of the connections queue
    proxySocket.listen(10)

    while True:
        clientSocket, ipAddrress = proxySocket.accept()

        print ("Accepted connection from: ", ipAddrress)

        clientThread = threading.Thread(
            target=processClientRequest, args=(clientSocket, ipAddrress, apiKey), daemon=True)

        clientThread.start()

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
    return error.encode()


def processClientRequest(clientSocket, ipAddress, apiKey):
    """
    processClientRequest is given the clientSocket and receives
    the requested message. A connection to the destination server
    is established if no errors were found in the message. The
    serverResponse is forwared to the client and all connections
    are closed.
    """

    clientSocket.send(str.encode("Please enter your request below: \r\n\r\n"))
    print ("\nReading data from: ", clientSocket.getpeername())

    requestMessage = b""
    while True:
        clientRequest = clientSocket.recv(4096)

        if clientRequest.decode() == "\r\n":
            break

        requestMessage += clientRequest

    requestMessage = requestMessage.decode().strip()

    # If the requestMessage is empty, return a 400 Bad Request response
    if not requestMessage:
        print ("Empty request")
        clientSocket.send(errorMessage("400 Bad Request"))
        clientSocket.close()

        print ("\nWaiting for connection\n")
        return None

    requestLine = requestMessage.split("\n")[0].split(" ")

    # If the request line is not formatted properly, return a 400 Bad
    # Request response
    if len(requestLine) != 3:
        print ("Request formatted incorrectly")
        clientSocket.send(errorMessage("400 Bad Request"))
        clientSocket.close()

        print ("\nWaiting for connection\n")
        return None

    url = urlparse(requestLine[1])

    # If the method requested is not GET, return a 501 Not Implemented
    # response
    if requestLine[0] != "GET":
        print ("Incorrect method")
        clientSocket.send(errorMessage("501 Not Implemented"))
        clientSocket.close()

        print ("\nWaiting for connection\n")
        return None

    # Else if the URL is incorrectly formatted, return a 400 Bad Request response
    elif not (url.scheme and url.netloc):
        print ("URL incorrectly formatted")
        clientSocket.send(errorMessage("400 Bad Request"))
        clientSocket.close()

        print ("\nWaiting for connection\n")
        return None

    # Else if the HTTP/1.0 is not requested, return a 400 Bad Request response
    elif requestLine[2].strip() != "HTTP/1.0":
        print ("Incorrect HTTP version")
        clientSocket.send(errorMessage("400 Bad Request"))
        clientSocket.close()

        print ("\nWaiting for connection\n")
        return None

    # Build the request message from the client to the server
    serverRequest = "%s %s %s\r\n" % (
        requestLine[0], url.path, requestLine[2].strip())
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
        print ("Server socket creation failed with error: "), error
        clientSocket.send(errorMessage("502 Bad Gateway"))
        clientSocket.close()

        print ("\nWaiting for connection\n")
        return None

    serverSocket.send(serverRequest.encode())

    print ("Connecting to remote server: ", serverSocket.getpeername())

    checkResponse = b""
    while True:
        serverResponse = serverSocket.recv(4096)

        if not serverResponse:
            break

        checkResponse += serverResponse

    if checkResponse:
        # Split the received response at new line "\r\n\r\n"
        # splitResponse = checkResponse.decode("ISO-8859-1").split("\r\n\r\n", 1) <- need to check charset type to determine encode/decode
        splitResponse = checkResponse.decode().split("\r\n\r\n", 1)

        # Convert the serverResponse data (not including headers)
        # to MD5
        encMessage = hashlib.md5(splitResponse[1].encode()).hexdigest()

        # Set up VirusTotal connection
        VTurl = "https://www.virustotal.com/vtapi/v2/file/report"
        params = {
            "apikey": apiKey, "resource": encMessage}
        response = requests.get(VTurl, params=params)
        jsonResponse = response.json()

        # If the response from VirusTotal is empty, return 5xx Server Error
        if not jsonResponse:
            clientSocket.send(errorMessage("5xx Server Error"))

        # Else if the response from VirusTotal is not 1, the value sent
        # to VirusTotal was not found in their database, assume it is
        # "clean" and send server response to the client
        elif jsonResponse["response_code"] != 1:
            clientSocket.send(checkResponse)

        # Else the requested value was found in VirusTotal"s database
        else:

            # If no positive results were found, send server response
            # back to the client
            if jsonResponse["positives"] == 0:
                clientSocket.send(checkResponse)

            # Else malware was found, send server response header
            # and a content blocked message back to the client
            else:
                malwareResponse = splitResponse[0] + "\r\n\r\n"
                malwareResponse += "content blocked" + "\r\n\r\n"
                clientSocket.send(malwareResponse)

    print ("Closing remote server socket", serverSocket.getpeername())
    serverSocket.close()
    clientSocket.close()

    print ("\nWaiting for connection\n")
    return None


if __name__ == "__main__":
    main()
