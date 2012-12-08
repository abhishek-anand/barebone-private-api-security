barebone-private-api-security
=============================

A private api barebone implementation similar to 2 legged OAuth


Private API implementation almost similar to 2-legged OAuth
  1. User registers on the webpage gets a consumer_key and secret_key
  2. Keys corresponding to user saved in database
  3. To make a request user compacts data parameters to be sent along and a timestamp denoting the current time with the request and hashes it using his private key. 
  4. User sends this hash signature, the real data, consumer key and the timestamp. SECRET_KEY IS NEVER TRANSMITTED
  5. Server checks the consumer key, retrives the corresponding secret key from db and uses the data, timestamp, consumer and secret key to recreate the hash signature and matches it. If the user is wrong or timestamp has been modified in between the request is rejected.
