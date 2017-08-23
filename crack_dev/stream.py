import tweepy
from keys import *
import json


# Get Tweets for CipherEveryword
# new_tweets = api.user_timeline(screen_name = "CipherEveryword", count=200)

# This is the listener, resposible for receiving data
class StdOutListener(tweepy.StreamListener):
    def on_data(self, data):
        # Twitter returns data in JSON format - we need to decode it first
        print(data)

        decoded = json.loads(data)
        print(decoded['id'])
        print(decoded['text'].encode('ascii', 'ignore'))
        # Also, we convert UTF-8 to ASCII ignoring all bad characters sent by users

        #print(decoded['text'].encode('ascii', 'ignore'), decoded['id'].encode('ascii', 'ignore'))
        tweet_text = decoded['text'].encode('ascii', 'ignore')
        tweet_id = decoded['id']
        print("Tweet Text : ", tweet_text)
        print("Tweet ID:    ", tweet_id)
        print('')
        return True

    def on_error(self, status):
        print(status)



l = StdOutListener()
auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
auth.set_access_token(access_token, access_token_secret)
print("Showing all new tweets for #CipherEveryWord:")

# There are different kinds of streams: public stream, user stream, multi-user streams
# In this example follow #programming tag
# For more details refer to https://dev.twitter.com/docs/streaming-apis
stream = tweepy.Stream(auth, l)
# stream tweets from my followers
#stream.userstream("with=following")
# Stream tweets containing hacking
#stream.filter(track=['malware'])
# get all Tweets from user http://gettwitterid.com/?user_name=
stream.filter(follow=['897020784144781312'])
