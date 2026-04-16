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
    
    allowOrigin = functionResponse.headers.get("Access-Control-Allow-Origin")
    allowCreds = functionResponse.headers.get("Access-Control-Allow-Credentials")
    
    print(functionResponse.headers) # testing print (remove later)
    print(allowOrigin) # testing print (remove later)
    print(allowCreds) # testing print (remove later)
    
   # return the relevant headers for analysis function
    allowOrigin, allowCreds
    
def analyze_repsonse(url, allowOrigin, allowCreds):
    # analyze the response headers for CORS misconfigurations
    # take the repsonse from the previous function and analyze it here
    
    # setup variables for analysis
    # the scoring system will be like golf, the lower the better, with 0 being the best
    allowOriginScore = 0
    allowCredsScore = 0
    
    # allowOrigin
    if allowOrigin is None:
        print("No CORS origin headers found in response")
    
    
    # allowCreds
    if allowCreds is None:
        print("No CORS credentials headers found in response")
        
    
    # anaylze the CORS
    
    
    # grades based on analysis
    
    # return everything to pass into the print function for final report
    
    
def main():
    print("CORS Misconfiguration Scanner")
    
    # get user url
    tarURL = get_user_url()
    print(tarURL) # testing print (remove later)
    
    # check user url validity
    check_user_url(tarURL)
    
    # send request
    corsHeader, corsHeaderCreds = send_request(tarURL)
    
    # analyze response
    analyze_repsonse(tarURL, corsHeader, corsHeaderCreds)
    
    # when we recieve the response from the GET request, it comes in the form of a dictionary
    # each key in the dictionary has a "definition" linked to it, I am not sure that is the correct term
    # 1. Ensure the return includes CORS entries
    # 2. Read the definition linked to the CORS key
    # 3. Grade the definition based on predeterminded scoring
    
    
    # report results


if __name__ == "__main__":
    main()