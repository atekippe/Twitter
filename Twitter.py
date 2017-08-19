import tweepy
import re
import base64
import subprocess
from keys import *
import enchant
import time
import binascii

debug = ''


def debug_info(raw_hash, hash_type):
    # print(raw_hash, hash_type)
    pass


def unknown_write(unknown_data):

    file_path = '/tmp/hashes/unknown.txt'

    try:
        # path to the file
        # open the file, a appends data
        out_file = open(file_path, 'a')
        # write the data
        out_file.write(unknown_data)
        # if you need a new line
        out_file.write("\n")
        # close the file
        out_file.close()

    except IOError as e:
        print(e)


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


def rot_break(data):
    # get an english Dictionary
    d = enchant.Dict("en_US")
    # roll the bits and look for an english word
    i = 0
    while i < 26:

        decoded = rot_decode(data, i)
        is_english = d.check(decoded)
        print(decoded, is_english)
        if is_english is True:
            print(decoded, is_english)
            return decoded
            break
        else:
            i += 1
    unknown_write(data)
    return "Not Cracked"


def go_slower():
    print("Sleeping 3 minutes...")
    time.sleep(60)
    print("Sleeping 2 minutes...")
    time.sleep(60)
#    print("Sleeping 1 minute1...")
 #   time.sleep(30)
  #  print("Sleeping 30 seconds...")
   # time.sleep(30)


def should_we_tweet_live(cracked, tweet_id):
    if "Not Cracked" in cracked:
        print("Loser ", cracked)
    else:
        cracked_split = cracked.split()
        to_tweet = "@CipherEveryword " + cracked_split[0]
        try:
            print("Winner  ", cracked)
            # need to slow down the requests - 1 Tweet every 3 minutes on load
            go_slower()
            api.update_status(status=to_tweet, in_reply_to_status_id=tweet_id)
        except tweepy.TweepError as e:
            print(e)


def crack_stuff(crack_hash, f_format):

    file_path = '/tmp/hashes/' + crack_hash
    to_write = crack_hash + ":" + crack_hash
    # get rid of the pot file
    # clean_up = 'rm ' + file_path + '&& rm /tmp/hashes/test'
    # Keep the pot file
    clean_up = 'rm ' + file_path

    # Regex to check the John output for success
    filter_cracked = re.compile(crack_hash)

    # dict_path = "/home/atekippe/Desktop/rockyou.txt"
    dict_path = "/home/atekippe/Desktop/words.txt"
    # dict_path = "/home/atekippe/Desktop/realhuman_phill.txt"

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

    return "Not Cracked"


def binary_decode(binary_data):

    hex_bin = hex(int((binary_data[2:]), 2))
    decoded_binary = (binascii.unhexlify(hex_bin[2:]))
    print("Binary decoded : ", decoded_binary.decode("utf-8"))
    return decoded_binary.decode("utf-8")


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
# the \ is necessary to escape the '
filter_caesar = re.compile('^[a-zA-z\']*$')

# Login to Twitter
auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
auth.set_access_token(access_token, access_token_secret)
api = tweepy.API(auth)

# Get Tweets for CipherEveryword
new_tweets = api.user_timeline(screen_name = "CipherEveryword", count=500)

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
                                    # print("No Match :", tweet.text)
                                    regex = re.search(filter_caesar, tweet.text)

                                    if regex is None:
                                        # print("No Match :", tweet.text)
                                        unknown_write(tweet.text)
                                    else:
                                        # Try to break the Rot N
                                        cracked = rot_break(tweet.text)
                                        should_we_tweet_live(cracked, tweetID)
                                else:
                                    # Try to decode the b64
                                    cracked = base64_decode(tweet.text)
                                    should_we_tweet_live(cracked, tweetID)
                            else:
                                hash_format = ["Raw-SHA512"]

                                # Debugging info
                                if debug is 'true':
                                    debug_info(tweet.text, hash_format)

                                cracked = crack_stuff(tweet.text, hash_format)
                                print(tweet.id_str)
                                should_we_tweet_live(cracked, tweetID)
                        else:
                            hash_format = ["Raw-SHA384"]

                            # Debugging info
                            if debug is 'true':
                                debug_info(tweet.text, hash_format)

                            cracked = crack_stuff(tweet.text, hash_format)
                            should_we_tweet_live(cracked, tweetID)
                    else:
                        hash_format = ["Raw-SHA256"]

                        # Debugging info
                        if debug is 'true':
                            debug_info(tweet.text, hash_format)

                        cracked = crack_stuff(tweet.text, hash_format)
                        should_we_tweet_live(cracked, tweetID)
                else:
                    hash_format = ["Raw-SHA224"]

                    # Debugging info
                    if debug is 'true':
                        debug_info(tweet.text, hash_format)

                    cracked = crack_stuff(tweet.text, hash_format)
                    should_we_tweet_live(cracked, tweetID)
            else:
                hash_format = ["ripemd-160", "Raw-SHA1"]  # , "Raw-SHA1-AxCrypt", "Raw-SHA1-Linkedin", "Raw-SHA1-ng", "has-160"]

                # Debugging info
                if debug is 'true':
                    debug_info(tweet.text, hash_format)

                cracked = crack_stuff(tweet.text, hash_format)
                should_we_tweet_live(cracked, tweetID)
        else:
            hash_format = ["raw-md5", "raw-md4", "MD2", "ripemd-128", "hmac-md5"]  # , "HAVAL-128-4", "LM", "dynamic=md5($p)", "mdc2", "mscash", "NT", "Raw-MD5u", "Raw-SHA1-AxCrypt", "Snefru-128", "NT-old"]

            # Debugging info
            if debug is 'true':
                debug_info(tweet.text, hash_format)

            cracked = crack_stuff(tweet.text, hash_format)
            should_we_tweet_live(cracked, tweetID)
    else:
        # Submit the decoded Binary
        cracked = binary_decode(tweet.text)
        should_we_tweet_live(cracked, tweetID)



