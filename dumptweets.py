import tweepy
from keys import *




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
