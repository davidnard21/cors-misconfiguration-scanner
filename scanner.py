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
    spacer = "=============================="
    # send a request to the url and get the response
    # the information returned from the reponse will be used to analyze the CORS config
    
    # after getting the simple GET request working and polished
    # I will add a preflight more indepth request to pull the rest of the headers from the server for further testing
    
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
        
    # get the response headers
    # create headers dictionary to avoid passing a million vars for each function

    corsHeaders = {
        "allowOrigin": functionResponse.headers.get("Access-Control-Allow-Origin", "N/A"),
        "allowCreds": functionResponse.headers.get("Access-Control-Allow-Credentials", "N/A"),
        "allowMethods": functionResponse.headers.get("Access-Control-Allow-Methods", "N/A"),
        "allowControl": functionResponse.headers.get("Access-Control-Allow-Headers", "N/A"),
        "exposeHeaders": functionResponse.headers.get("Access-Control-Expose-Headers", "N/A"),
        "controlMaxAge": functionResponse.headers.get("Access-Control-Max-Age", "N/A")
    }
    
    print(spacer)
    print(functionResponse.headers) # testing print (remove later)
    print("Origin : " + corsHeaders["allowOrigin"])
    print("Credentials : " + corsHeaders["allowCreds"])
    print("Methods : " + corsHeaders["allowMethods"])

    # return the relevant headers for analysis function
    return corsHeaders
    
def analyze_repsonse(url, allowOrigin, allowCreds):
    # analyze the response headers for CORS misconfigurations
    # take the repsonse from the previous function and analyze it here
   
    # return everything to pass into the print function for final report

    pass
    

def main():
    print("CORS Misconfiguration Scanner")
    
    # get user url
    tarURL = get_user_url()
    print(tarURL) # testing print (remove later)
    
    # check user url validity
    check_user_url(tarURL)
    
    # send request
    corsHeaders = send_request(tarURL)
    
    # analyze response
    analyze_repsonse(tarURL, corsHeaders["allowOrigin"], corsHeaders["allowCreds"],)
    
    # when we recieve the response from the GET request, it comes in the form of a dictionary
    # each key in the dictionary has a "definition" linked to it, I am not sure that is the correct term
    # 1. Ensure the return includes CORS entries
    # 2. Read the definition linked to the CORS key
    # 3. Grade the definition based on predeterminded scoring
    
    
    # report results


if __name__ == "__main__":
    main()
