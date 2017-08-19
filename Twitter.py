import tweepy
import re
import base64
import subprocess
from keys import *


def rot_decode(story, shift):
    #  https://stackoverflow.com/questions/8886947/caesar-cipher-function-in-python
    return ''.join([  # concentrate list to string
            (lambda c, is_upper: c.upper() if is_upper else c)  # if original char is upper case than convert result to upper case too
                (
                  ("abcdefghijklmnopqrstuvwxyz"*2)[ord(char.lower()) - ord('a') + shift % 26],  # rotate char, this is extra easy since Python accepts list indexs below 0
                  char.isupper()
                )
            if char.isalpha() else char  # if not in alphabet then don't change it
            for char in story
        ])


def should_we_tweet_live(cracked, tweet_id):
    if "Not Cracked" in cracked:
        print("Loser ", cracked)
    else:

        cracked_split = cracked.split()
        to_tweet = "@CipherEveryword " + cracked_split[0]
        try:
            print("Winner  ", cracked)
            # api.update_status(status=to_tweet, in_reply_to_status_id=tweet_id)
        except tweepy.TweepError as e:
            print(e)


def crack_stuff(crack_hash, f_format):
    print(crack_hash, f_format)
    file_path = '/tmp/hashes/' + crack_hash
    to_write = crack_hash + ":" + crack_hash
    clean_up = 'rm ' + file_path + '&& rm /tmp/hashes/test'
    try:
        # path to the file
        # open the file, a appends data
        out_file = open(file_path, 'a')
        # write the data
        out_file.write(to_write)
        # if you need a new line
        out_file.write("\n")
        # close the file
        out_file.close()

    except IOError as e:
        print(e)

    # Regex to check the John output for success
    filter_cracked = re.compile(crack_hash)
    #dict_path = "/home/atekippe/Desktop/rockyou.txt"
    dict_path = "/home/atekippe/Downloads/realuniq.lst"

    """
    for i in f_format:
        print("Cracking : ", i)

        john_command = "/home/atekippe/Desktop/CTF/utils/john-jumbo/john --format=" + i + " " + file_path + " --wordlist=" + dict_path + " --pot=/tmp/hashes/test"
        # john-jumbo --format=raw-md5 md --wordlist=/home/atekippe/Desktop/rockyou.txt --pot=test
        output = subprocess.getoutput([john_command])

        split_output = output.splitlines()
        # John is giving inconsistent output lengths, parse each line with regex to see if we recovered the password
        for l in split_output:
            # check to see if we cracked the hash
            regex = re.search(filter_cracked, l)
            if regex:
                subprocess.getoutput([clean_up])
                return l

    # clean_up the temp files
    subprocess.getoutput([clean_up])
    try:
        # path to the file
        # open the file, a appends data
        out_file = open("/tmp/hashes/no_crack.txt", 'a')
        # write the data
        out_file.write(crack_hash)
        # if you need a new line
        out_file.write("\n")
        # close the file
        out_file.close()

    except IOError as e:
        print(e)
"""
    return "Not Cracked"


def binary_decode(binary_data):

    print(binary_data[2:])
    #print(chr(int(binary_data[2:], 2)))


# functions to reverse data
def base64_decode(b64_data):
    filter_alphanumeric = re.compile('^[a-zA-Z0-9_]*$')

    try:
        decoded = base64.b64decode(b64_data)

        try:
            str_decoded = str(decoded, 'utf-8')
            if re.search(filter_alphanumeric, str_decoded) is not None:
                print("Base64 is: ", str_decoded)
                return str_decoded
        except Exception:
            pass
    except IOError as e:
        print(e)

    return "Not Cracked"





# Regexes to match data posted
filter_binary = re.compile('0b[0-1]{8}')
filter_base64 = re.compile('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$')
# Matches MD2 / MD4 / MD5
filter_md4 = re.compile('^[0-9a-fA-F]{32}$')
# SHA1 or ripMD160
filter_ripMD160 = re.compile('^[0-9a-fA-F]{40}$')
filter_sha224 = re.compile('^[0-9a-fA-F]{56}$')
filter_sha256 = re.compile('^[0-9a-fA-F]{64}$')
filter_sha384 = re.compile('^[0-9a-fA-F]{96}$')
filter_sha512 = re.compile('^[0-9a-fA-F]{128}$')




# Login to Twitter
auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
auth.set_access_token(access_token, access_token_secret)
api = tweepy.API(auth)

# post a tweet
#api.update_status("TEST TWEET!")


# Get Tweets for CipherEveryword
new_tweets = api.user_timeline(screen_name = "CipherEveryword", count=200)

# Parse the tweets
for tweet in new_tweets:

    tweetID = tweet.id_str
    #print(tweet.text)
    """
    
    print(tweet.id_str)
    print(tweet.created_at) 
    """
    regex = re.search(filter_binary, tweet.text)

    #Check Binary first
    if regex is None:
        # Wasn't Binary, Lets check for md2 / md4 / md5
        regex = re.search(filter_md4, tweet.text)
        if regex is None:
            # Wasn't md4 lets check RIP160 / SHA 1
            regex = re.search(filter_ripMD160, tweet.text)
            if regex is None:
                # Wasn't RIP160 lets try SHA224
                regex = re.search(filter_sha224, tweet.text)
                if regex is None:
                    # Wasn't SHA224 lets try SHA256
                    regex = re.search(filter_sha256, tweet.text)
                    if regex is None:
                        # Wasn't SHA256, Maybe SHA384?
                        regex = re.search(filter_sha384, tweet.text)
                        if regex is None:
                            # Wasn't SHA384, SHA512?
                            regex = re.search(filter_sha512, tweet.text)
                            if regex is None:
                                # Maybe base64?
                                regex = re.search(filter_base64, tweet.text)
                                if regex is None:
                                    print("No Match :", tweet.text)
                                else:
                                    # Try to decode the b64
                                    cracked = base64_decode(tweet.text)
                                    should_we_tweet_live(cracked, tweetID)
                            else:
                                #print("We have SHA512: ", tweet.text)
                                hash_format = ["Raw-SHA512"]
                                cracked = crack_stuff(tweet.text, hash_format)
                                print(tweet.id_str)
                                should_we_tweet_live(cracked, tweetID)
                        else:
                            #print("We have SHA 384: ", tweet.text)
                            hash_format = ["Raw-SHA384"]
                            cracked = crack_stuff(tweet.text, hash_format)
                            should_we_tweet_live(cracked, tweetID)
                    else:
                        #print("We have SHA256: ", tweet.text)
                        hash_format = ["Raw-SHA256"]
                        cracked = crack_stuff(tweet.text, hash_format)
                        should_we_tweet_live(cracked, tweetID)
                else:
                    #print("We have SHA224: ", tweet.text) Raw-SHA224
                    hash_format = ["Raw-SHA224"]
                    cracked = crack_stuff(tweet.text, hash_format)
                    should_we_tweet_live(cracked, tweetID)
            else:
                # print("We have RIP160: ", tweet.text)
                hash_format = ["ripemd-160", "Raw-SHA1"]
                cracked = crack_stuff(tweet.text, hash_format)
                should_we_tweet_live(cracked, tweetID)
        else:
            # print("We have and MD2 / MD4: ", tweet.text)
            # john formats MD2 = MD2, MD4 = raw-md4, MD5 = raw-md5
            hash_format = ["raw-md5", "raw-md4", "MD2"]
            cracked = crack_stuff(tweet.text, hash_format)
            should_we_tweet_live(cracked, tweetID)
    else:
        #print("We have Binary: ", tweet.text)
        binary_decode(tweet.text)



