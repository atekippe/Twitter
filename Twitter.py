#!/usr/bin/python3
import json
import tweepy
import re
import base64
import subprocess
from keys import *
import enchant
import binascii
import sys


def unknown_write(unknown_data):
    # Messy global variable to fix pathing issues....
    global project_path

    # path to the file
    file_path = project_path + 'unknown.txt'

    try:
        # write the data
        out_file = open(file_path, 'a')
        out_file.write(unknown_data)
        out_file.write("\n")
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
    # Messy global variable to fix pathing issues....
    global project_path
    # get an english Dictionary and add a custom word list
    dict_path = project_path + "words.txt"
    d = enchant.DictWithPWL("en_US", dict_path)
    # roll the letters and look for an english word
    i = 0
    while i < 26:

        decoded = rot_decode(data, i)

        is_english = d.check(decoded)
        # print(decoded, is_english)
        if is_english is True:
            print(decoded, is_english)
            return decoded

        else:
            i += 1
    unknown_write(data)
    return "Not Cracked"


def new_solve(cracked, tweet_id):
    # Messy global variable to fix pathing issues....
    global project_path
    tweet_id_path = project_path + 'tweetID_solved.txt'
    try:
        # read a file to a variable
        solved_file = open(tweet_id_path, 'r')

        for solved in solved_file:
            solve_clean = str(solved).rstrip()
            if tweet_id in solve_clean:
                print("Already Solved!", cracked, solve_clean, tweet_id)
                solve = 1
                break
            else:
                solve = 0

        solved_file.close()

        return solve

    except IOError as e:
        print(e)


def update_solve_file(tweet_id):
    # Messy global variable to fix pathing issues....
    global project_path
    tweet_id_solve_path = project_path + 'tweetID_solved.txt'

    try:
        # write the data
        solved_file = open(tweet_id_solve_path, 'a')
        solved_file.write(tweet_id)
        solved_file.write("\n")
        solved_file.close()
        print("Updated Solved File")
    except IOError as e:
        print(e)


def should_we_tweet_live(cracked, tweet_id):
    if "Not Cracked" in cracked:
        print("Loser ", cracked)
    else:
        auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
        auth.set_access_token(access_token, access_token_secret)
        api = tweepy.API(auth)
        cracked_split = cracked.split()
        to_tweet = "@CipherEveryword " + cracked_split[0]
        print("Winner  ", cracked, tweet_id)

        # update the solved file with the tweet ID so we don't double solve
        update_solve_file(tweet_id)

        # Tweet the reply
        try:
            api.update_status(status=to_tweet, in_reply_to_status_id=tweet_id)
        except tweepy.TweepError as e:
            print(e)


def crack_stuff(crack_hash, f_format):
    # Messy global variable to fix pathing issues....
    global project_path

    # file path variables
    file_path = project_path + crack_hash
    dict_path = project_path + "words.txt"

    # we are going to write hashes to temp files as hash:hash for John to read
    to_write = crack_hash + ":" + crack_hash
    
    # Command to clean up temp files
    clean_up = 'rm ' + file_path

    # Regex to check the John output for success
    filter_cracked = re.compile(crack_hash)

    try:
        # write the temp file for cracking
        out_file = open(file_path, 'a')
        out_file.write(to_write)
        out_file.write("\n")
        out_file.close()

    except IOError as e:
        print(e)

    # several hash formats were passed to the function.  We are going to loop them until we solve
    for i in f_format:
        print("Cracking : ", i)

        # command to run John
        john_command = "/home/atekippe/tools/john-jumbo/john --format=" + i + " " + file_path + " --wordlist=" + dict_path + " --pot=solve.pot"
        
        # run John
        output = subprocess.getoutput([john_command])

        # the output was ugly.  We have to parse it.
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
        no_crack_path = project_path + "no_crack.txt"
        # we didn't crack, so we are writing the hash to the no_crack file
        out_file = open(no_crack_path, 'a')
        out_file.write(crack_hash)
        out_file.write("\n")
        out_file.close()

    except IOError as e:
        print(e)

    return "Not Cracked"


def binary_decode(binary_data):

    hex_bin = hex(int((binary_data[2:]), 2))
    decoded_binary = (binascii.unhexlify(hex_bin[2:]))
    print("Binary decoded : ", decoded_binary.decode("utf-8"))
    return decoded_binary.decode("utf-8")


def base64_decode(b64_data):
    filter_alphanumeric = re.compile('^[a-zA-Z0-9_-]*$')
    # Messy global variable to fix pathing issues....
    global project_path

    try:
        decoded = base64.b64decode(b64_data)

        try:
            str_decoded = str(decoded, 'utf-8')

            # if the result is alpha numeric we solved it
            if re.search(filter_alphanumeric, str_decoded) is not None:
                print("Base64 is: ", str_decoded)
                return str_decoded
            
        except Exception:
            try:
                base64_decoded_path = project_path + 'b64_notdecoded.txt'
                # We didn't recover so write the b64 to the b64_notdecoded file
                b64_file = open(base64_decoded_path, 'a')
                b64_file.write(b64_data)
                b64_file.write("\n")
                b64_file.close()
                print("Updated b64_notdecoded.txt")
            except IOError as e:
                print(e)
            pass
    except IOError as e:
        print(e)

    return "Not Cracked"


def process_data(tweet_data, tweet_id):
    # Regex to match data posted
    filter_binary = re.compile('0b[0-1]{8}')
    filter_base64 = re.compile('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$')
    filter_md4 = re.compile('^[0-9a-fA-F]{32}$')  # Matches MD2 / MD4 / MD5
    filter_ripmd160 = re.compile('^[0-9a-fA-F]{40}$')  # SHA1 or ripMD160
    filter_sha224 = re.compile('^[0-9a-fA-F]{56}$')
    filter_sha256 = re.compile('^[0-9a-fA-F]{64}$')
    filter_sha384 = re.compile('^[0-9a-fA-F]{96}$')
    filter_sha512 = re.compile('^[0-9a-fA-F]{128}$')
    filter_caesar = re.compile('^[a-zA-z\']*$')  # the \ is necessary to escape the '

    already_solved = new_solve(tweet_data, tweet_id)
    if already_solved is 1:
        # print("Already Solved!  ", tweetData, tweet_id)
        pass
    else:
        print("Not Solved")

        regex = re.search(filter_binary, tweet_data)

        # Check Binary first
        if regex is None:
            # Wasn't Binary, Lets check for md2 / md4 / md5
            regex = re.search(filter_md4, tweet_data)
            if regex is None:
                # Wasn't md4 lets check RIP160 / SHA 1
                regex = re.search(filter_ripmd160, tweet_data)
                if regex is None:
                    # Wasn't RIP160 lets try SHA224
                    regex = re.search(filter_sha224, tweet_data)
                    if regex is None:
                        # Wasn't SHA224 lets try SHA256
                        regex = re.search(filter_sha256, tweet_data)
                        if regex is None:
                            # Wasn't SHA256, Maybe SHA384?
                            regex = re.search(filter_sha384, tweet_data)
                            if regex is None:
                                # Wasn't SHA384, SHA512?
                                regex = re.search(filter_sha512, tweet_data)
                                if regex is None:
                                    # Maybe base64?
                                    regex = re.search(filter_base64, tweet_data)
                                    if regex is None:
                                        # print("No Match :", tweetData)
                                        regex = re.search(filter_caesar, tweet_data)

                                        if regex is None:
                                            # print("No Match :", tweetData)
                                            unknown_write(tweet_data)
                                        else:
                                            # Try to break the Rot N
                                            cracked = rot_break(tweet_data)
                                            should_we_tweet_live(cracked, tweet_id)
                                    else:
                                        # Try to decode the b64
                                        cracked = base64_decode(tweet_data)
                                        should_we_tweet_live(cracked, tweet_id)
                                else:
                                    hash_format = ["Raw-SHA512"]

                                    cracked = crack_stuff(tweet_data, hash_format)
                                    should_we_tweet_live(cracked, tweet_id)
                            else:
                                hash_format = ["Raw-SHA384"]

                                cracked = crack_stuff(tweet_data, hash_format)
                                should_we_tweet_live(cracked, tweet_id)
                        else:
                            hash_format = ["Raw-SHA256"]

                            cracked = crack_stuff(tweet_data, hash_format)
                            should_we_tweet_live(cracked, tweet_id)
                    else:
                        hash_format = ["Raw-SHA224"]

                        cracked = crack_stuff(tweet_data, hash_format)
                        should_we_tweet_live(cracked, tweet_id)
                else:
                    hash_format = ["ripemd-160", "Raw-SHA1"]  # , "Raw-SHA1-AxCrypt", "Raw-SHA1-Linkedin", "Raw-SHA1-ng", "has-160"]

                    cracked = crack_stuff(tweet_data, hash_format)
                    should_we_tweet_live(cracked, tweet_id)
            else:
                hash_format = ["raw-md5", "raw-md4", "MD2", "ripemd-128", "hmac-md5"]  # , "HAVAL-128-4", "LM", "dynamic=md5($p)", "mdc2", "mscash", "NT", "Raw-MD5u", "Raw-SHA1-AxCrypt", "Snefru-128", "NT-old"]

                cracked = crack_stuff(tweet_data, hash_format)
                should_we_tweet_live(cracked, tweet_id)
        else:
            # Submit the decoded Binary
            cracked = binary_decode(tweet_data)
            should_we_tweet_live(cracked, tweet_id)


# This is the listener, responsible for receiving data
class StdOutListener(tweepy.StreamListener):
    def on_data(self, data):
        # Twitter returns data in JSON format - we need to decode it first
        decoded = json.loads(data)
        tweet_text = decoded['text']
        tweet_id = str(decoded['id'])

        print("Tweet Text : ", tweet_text)
        print("Tweet ID   : ", tweet_id)
        print('')

        # Filter my replies from data processing.  All of the replies contain @CipherEveryword
        if "@CipherEveryword" not in tweet_text:
            process_data(tweet_text, tweet_id)

        return True

    def on_error(self, status):
        print(status)


def stream_tweets():

    l = StdOutListener()

    auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
    auth.set_access_token(access_token, access_token_secret)

    print("Showing all new tweets for #CipherEveryWord:")
    stream = tweepy.Stream(auth, l)
    # stream tweets from my followers
    # stream.userstream("with=following")
    # Stream tweets containing hacking
    # stream.filter(track=['malware'])
    # get all Tweets from user http://gettwitterid.com/?user_name=338014764
    stream.filter(follow=['897020784144781312'])
    # aaron_tekippe
    # stream.filter(follow=['338014764'])


def parse_tweets():
    # Login to Twitter
    auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
    auth.set_access_token(access_token, access_token_secret)
    api = tweepy.API(auth)

    # Get Tweets for CipherEveryword
    new_tweets = api.user_timeline(screen_name="CipherEveryword", count=20)

    # loop the tweets and process if not solved
    for tweet in new_tweets:

        tweet_text = tweet.text
        tweet_id = tweet.id_str

        already_solved = new_solve(tweet.text, tweet_id)
        if already_solved is 1:
            pass
        else:
            process_data(tweet_text, tweet_id)


def parse_all_tweets():

    # Login to Twitter
    auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
    auth.set_access_token(access_token, access_token_secret)
    api = tweepy.API(auth)

    # Get Tweets for CipherEveryword
    new_tweets = api.user_timeline(screen_name = "CipherEveryword", count=200)

    # GET ALL THE TWEETS....
    all_tweets = []
    # save most recent tweets
    all_tweets.extend(new_tweets)

    # save the id of the oldest tweet less one
    oldest = all_tweets[-1].id - 1

    # keep grabbing tweets until there are no tweets left to grab
    while len(new_tweets) > 0:
        print("getting tweets before %s" % (oldest))

        # all subsequent requests use the max_id param to prevent duplicates
        new_tweets = api.user_timeline(screen_name="CipherEveryword", count=200, max_id=oldest)

        # save most recent tweets
        all_tweets.extend(new_tweets)

        # update the id of the oldest tweet less one
        oldest = all_tweets[-1].id - 1

        print("...%s tweets downloaded so far" % (len(all_tweets)))

        # loop the tweets and process if not solved
        for tweet in all_tweets:

            tweet_text = tweet.text
            tweet_id = tweet.id_str

            already_solved = new_solve(tweet.text, tweet_id)
            if already_solved is 1:
                pass
            else:
                print("Not Solved")
                process_data(tweet_text, tweet_id)



def print_help():
    print("Usage: python3 Twitter.py <mode>")
    print("Modes: ")
    print("      -s or --stream: Stream tweets")
    print("      -p or --parse: Parse last 200 tweets")
    print("      -a or --all: Parse all tweets")

if __name__ == "__main__":

    help_message = "Usage: python3 Twitter.py <mode>\n"
    if len(sys.argv) < 2:
        print('Usage: python3 ' + sys.argv[0] + ' <mode>')
        sys.exit(0)

    mode = sys.argv[1]
    if mode in ("-h", "--help"):
        print_help()
    elif mode in ("-s", "--stream"):
        stream_tweets()
    elif mode in ("-p", "--parse"):
        parse_tweets()
    elif mode in ("-a", "--all"):
        parse_all_tweets()
    else:
        print_help()
