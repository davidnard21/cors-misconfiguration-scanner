import sys
import os
import re
import json
import logging
import requests
from urllib.parse import urlparse

# utility functions

def littleSpacer():
    print("-" * 60)

def bigSpacer():
    print("=" * 60)
    
def title():
    print("=" * 20 + "CORS HEADER SCANNER" + "=" * 21)
    
def results():
    print("=" * 26 + "RESULTS" + "=" * 27)

# main functionality functions

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
    
def send_request(url, corsHeaders):
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
    
    corsHeaders["allowOrigin"] = functionResponse.headers.get("Access-Control-Allow-Origin", "N/A")
    corsHeaders["allowCreds"] = functionResponse.headers.get("Access-Control-Allow-Credentials", "N/A")
    corsHeaders["allowMethods"] = functionResponse.headers.get("Access-Control-Allow-Methods", "N/A")
    corsHeaders["allowControl"] = functionResponse.headers.get("Access-Control-Allow-Headers", "N/A")
    corsHeaders["exposeHeaders"] = functionResponse.headers.get("Access-Control-Expose-Headers", "N/A")
    corsHeaders["controlMaxAge"] = functionResponse.headers.get("Access-Control-Max-Age", "N/A")
    
    bigSpacer()
    print(functionResponse.headers) # testing print (remove later)
    # print("Origin : " + corsHeaders["allowOrigin"])
    # print("Credentials : " + corsHeaders["allowCreds"])
    # print("Methods : " + corsHeaders["allowMethods"])

    # return the relevant headers for analysis function
    return corsHeaders
    
def analyze_repsonse(tarURL, corsHeaders):
    # analyze the response headers for CORS misconfigurations
    # take the repsonse from the previous function and analyze it here
    
    # print all the stats for the user
    
    results()
    
    print(f"{'Allow Origin':<25}: " + corsHeaders["allowOrigin"])
    print(f"{'Allow Credentials':<25}: " + corsHeaders["allowCreds"])
    print(f"{'Allow Methods':<25}: " + corsHeaders["allowMethods"])
    print(f"{'Allow Control':<25}: " + corsHeaders["allowControl"])
    print(f"{'Expose Headers':<25}: " + corsHeaders["exposeHeaders"])
    print(f"{'Control Max Age':<25}: " + corsHeaders["controlMaxAge"])
    
    # print the juice
    # make sure they know about the deadly combos
    
    if corsHeaders["allowOrigin"] == "http://evil.com" and corsHeaders["allowCreds"] == "true":
        littleSpacer()
        print(f"{'Allow Origin':<25}: " + corsHeaders["allowOrigin"])
        print(f"{'Allow Credentials':<25}: " + corsHeaders["allowCreds"])
        print(f"{'Verdict':<25}: " + "CRITICAL [!!!]")
    if corsHeaders["allowOrigin"] == "null" and corsHeaders["allowCreds"] == "true":
        littleSpacer()
        print(f"{'Allow Origin':<25}: " + corsHeaders["allowOrigin"])
        print(f"{'Allow Credentials':<25}: " + corsHeaders["allowCreds"])
        print(f"{'Verdict':<25}: " + "HIGH [!!]")
    if corsHeaders["allowOrigin"] == "*" and corsHeaders["allowCreds"] == "true":
        littleSpacer()
        print(f"{'Allow Origin':<25}: " + corsHeaders["allowOrigin"])
        print(f"{'Allow Credentials':<25}: " + corsHeaders["allowCreds"])
        print(f"{'Verdict':<25}: " + "MEDIUM [!]")
    if corsHeaders["allowOrigin"] == "http://evil.com" and corsHeaders["allowCreds"] == "false":
        littleSpacer()
        print(f"{'Allow Origin':<25}: " + corsHeaders["allowOrigin"])
        print(f"{'Allow Credentials':<25}: " + corsHeaders["allowCreds"])
        print(f"{'Verdict':<25}: " + "MEDIUM [!]")
    if corsHeaders["allowOrigin"] == "*" and corsHeaders["allowCreds"] == "false":
        littleSpacer()
        print(f"{'Allow Origin':<25}: " + corsHeaders["allowOrigin"])
        print(f"{'Allow Credentials':<25}: " + corsHeaders["allowCreds"])
        print(f"{'Verdict':<25}: " + "LOW")
    if corsHeaders["allowOrigin"] == "null" and corsHeaders["allowCreds"] == "false":
        littleSpacer()
        print(f"{'Allow Origin':<25}: " + corsHeaders["allowOrigin"])
        print(f"{'Allow Credentials':<25}: " + corsHeaders["allowCreds"])
        print(f"{'Verdict':<25}: " + "LOW")
    if corsHeaders["allowOrigin"] == tarURL and corsHeaders["allowCreds"] == "true":
        littleSpacer()
        print(f"{'Allow Origin':<25}: " + corsHeaders["allowOrigin"])
        print(f"{'Allow Credentials':<25}: " + corsHeaders["allowCreds"])
        print(f"{'Verdict':<25}: " + "SAFE")
    if corsHeaders["allowOrigin"] == "N/A" and corsHeaders["allowCreds"] == "N/A":
        littleSpacer()
        print(f"{'Allow Origin':<25}: " + corsHeaders["allowOrigin"])
        print(f"{'Allow Credentials':<25}: " + corsHeaders["allowCreds"])
        print(f"{'Verdict':<25}: " + "SAFE")

def main():
    # define main dictionary to handle lons of variables
    corsHeaders = {
        # header config
        "allowOrigin": "N/A",
        "allowCreds": "N/A",
        "allowMethods": "N/A",
        "allowControl": "N/A",
        "exposeHeaders": "N/A",
        "controlMaxAge": "N/A",    
    }
    
    # print title and ASCII art
    title()
    
    # get user url
    tarURL = get_user_url()
    print(tarURL) # testing print (remove later)
    
    # check user url validity
    check_user_url(tarURL)
    
    # send request
    send_request(tarURL, corsHeaders)
    
    # analyze response
    analyze_repsonse(tarURL, corsHeaders)
    
    # when we recieve the response from the GET request, it comes in the form of a dictionary
    # each key in the dictionary has a "definition" linked to it, I am not sure that is the correct term
    # 1. Ensure the return includes CORS entries
    # 2. Read the definition linked to the CORS key
    # 3. Grade the definition based on predeterminded scoring
    
    
    # report results
    


if __name__ == "__main__":
    main()
