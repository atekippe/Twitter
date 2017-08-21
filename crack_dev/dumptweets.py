import tweepy
from keys import *
import binascii


# Login to Twitter
auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
auth.set_access_token(access_token, access_token_secret)
api = tweepy.API(auth)

# post a tweet
#api.update_status("TEST TWEET!")



# Get Tweets for CipherEveryword
new_tweets = api.user_timeline(screen_name = "CipherEveryword", count=200)
#new_tweets = api.user_timeline(screen_name = screen_name,count=200,max_id=oldest)

# new_tweets = api.user_timeline(screen_name=screen_name, count=200)

alltweets = []
# save most recent tweets
alltweets.extend(new_tweets)

# save the id of the oldest tweet less one
oldest = alltweets[-1].id - 1

# keep grabbing tweets until there are no tweets left to grab
while len(new_tweets) > 0:
    print("getting tweets before %s" % (oldest))

    # all subsiquent requests use the max_id param to prevent duplicates
    new_tweets = api.user_timeline(screen_name="CipherEveryword", count=200, max_id=oldest)

    # save most recent tweets
    alltweets.extend(new_tweets)

    # update the id of the oldest tweet less one
    oldest = alltweets[-1].id - 1

    print
    "...%s tweets downloaded so far" % (len(alltweets))

i = 0
for tweet in alltweets:

    print(tweet.text, tweet.id)
    i += 1

print(i)
