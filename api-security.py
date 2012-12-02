import time
import hashlib
import hmac
import binascii
import random
import base64
import urllib2
from urllib import urlencode

# Private API implementation almost similar to 2-legged OAuth
# 1. User registers on the webpage gets a consumer_key and secret_key
# 2. Keys corresponding to user saved in database
# 3. To make a request user compacts data parameters to be sent along 
#    and a timestamp denoting the current time 
#    with the request and hashes it using his private key. 
# 4. User sends this hash signature, the real data, consumer key
#    and the timestamp. SECRET_KEY IS NEVER TRANSMITTED
# 5. Server checks the consumer key, retrives the corresponding secret key
#    from db and uses the data, timestamp, consumer and secret key to
#    recreate the hash signature and matches it. If the user is wrong
#    or timestamp has been modified in between the request is rejected.

def generate_keys():
    """ generates a pair of public and private keys for a user """
    consumer_key = base64.encodestring(str(random.getrandbits(100)))
    secret_key = base64.encodestring(str(random.getrandbits(100)))
    return (consumer_key[:-1], secret_key[:-1])

def blobify_data(data):
    """ takes a dictionary of request parameters, compacts it
    and then encodes it """
    result = ''
    l_data = []
    for item in data:
        l_data.append((item, data[item]))
    l_data.sort()
    for item in l_data:
        result += str(item[0])
        result += '='
        result += str(item[1])
        result += '&'
    return (result[:-1]) #can be encoded before using

def generate_hash(blob, consumer_key, secret_key):
    """ generates a signature for given blobified data which can be
    transmitted through a HTTP request """
    key = '&'.join([consumer_key, secret_key])
    hashed = hmac.new(key, blob, hashlib.sha1)
    return binascii.b2a_base64(hashed.digest())[:-1]

def make_request(api_url, data, consumer_key, secret_key):
    """ make a HTTP POST request to the given url with given data,
    timestamp of request (which can be verified by server in case it
    is modified malaciously and the HMAC signature generated """
    data['TIMESTAMP'] = str(time.time())
    blob = blobify_data(data)
    hash_sign = generate_hash(blob, consumer_key, secret_key)
    # make a post req with data
    # header includes timestamp, hmac_sign_of_data, consumer_key
    req = urllib2.Request(api_url)
    req.add_header('HASH_SIGN', hash_sign)
    req.add_header('CONSUMER_KEY', consumer_key)
    req.add_header('TIMESTAMP', data['TIMESTAMP']) #not required
    try:
        resp = urllib2.urlopen(req, blob, 2000)
    except:
        resp = "{'status':'error'}"
    return resp # a json response for the given request params
    
    
