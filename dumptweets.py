import tweepy
from keys import *
import binascii


def multi_byte_reverse_xor(xored_data, xor_key):
    xor_bytes = binascii.unhexlify(xored_data)

    # take xor bytes to a string
    xor_str = xor_bytes.decode("utf-8")

    # xor the data
    clear_text = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(xor_str, cycle(xor_key)))
    print(clear_text)
    return clear_text


# Login to Twitter
auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
auth.set_access_token(access_token, access_token_secret)
api = tweepy.API(auth)

# post a tweet
#api.update_status("TEST TWEET!")


# Get Tweets for CipherEveryword
new_tweets = api.user_timeline(screen_name = "CipherEveryword", count=200)

for tweet in new_tweets:

    print(tweet.text)

key = "A"
cipher = "QuYPqltSnw9qdxqY"

print(multi_byte_reverse_xor(cipher, key))