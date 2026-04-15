import sys
import os
import re
import json
import logging
import requests
from urllib.parse import urlparse

def get_user_url():
    functionURL = input("Enter the URL to scan for CORS misconfigurations: ")
    return functionURL

def check_user_url(url):
    # check if the url is valid
    # this includes starting with http or https, and having a valid domain
    
    # split url into components
    parsedURL = urlparse(url)
    
    # check if the scheme is http or https
    if parsedURL.scheme not in ["http", "https"]:
        print("Invalid URL: URL must start with http:// or https://")
        get_user_url() # ask user for url again
    if not parsedURL.netloc:
        print("Invalid URL: URL must have a valid domain")
        get_user_url() # ask user for url again
    if parsedURL.netloc == "":
        print("Invalid URL: URL must have a valid domain")
        get_user_url() # ask user for url again
    
    print("URL is valid") # testing print (remove later)
    
def send_request(url):
    # send a request to the url and get the response
    # the information returned from the reponse will be used to analyze the CORS config
    
    # create custom origin header for testing
    
    evilOriginHeader = {"Origin":"http://evil.com"}
    
    functionResponse = requests.get(url, headers=evilOriginHeader)
    
    # ensure good reponse by checking status code
    
    if functionResponse.status_code != 200:
        print("Request failed with status code: " + str(functionResponse.status_code))
        get_user_url() # ask user for url again
    else:
        # the only code that should be successful is code 200, but just in case print the status code
        print("Request successful with status code: " + str(functionResponse.status_code))
        
    # anaylze the response headers for CORS misconfig
    
    corsHeader = functionResponse.headers.get("Access-Control-Allow-Origin")
    corsHeaderCreds = functionResponse.headers.get("Access-Control-Allow-Credentials")
    
    print(functionResponse.headers) # testing print (remove later)
    
    # for testing right now sort through header before migrating to analysis function
    
    
def main():
    print("CORS Misconfiguration Scanner")
    
    # get user url
    tarURL = get_user_url()
    print(tarURL) # testing print (remove later)
    
    # check user url validity
    check_user_url(tarURL)
    
    # send request
    send_request(tarURL)
    
    # analyze response
    
    # grade the configuration
    
    # report results


if __name__ == "__main__":
    main()