

# octopus-group-surveys-api
a simple python script to get information from the internal octopus group surveys api

https://octopusgroup.com.au/

### warning ⚠️ 
 **this probably goes against octopus group's terms of service so be careful not to get your account banned. educational purposes only or whatever**

# setting up
in `login.json` put in your phone number and password as such

```json
{
    "phone": "0412345678",
    "password": "somepassword"
}
```

optional: if you are wanting to use the money redeeming part of the script, include your account number and bsb as well
```json
    "bsb": "123456",
    "account_number": "123456789"
```

### solving cloudflare challenge

octopus group's firebase api key is required to regenerate authorization tokens. this firebase api key is generally static, but could possibly be changed in the future. finding the program uses [Flaresolverr](https://github.com/Flaresolverr/Flaresolverr), which needs to be hosted on the same device running this program. for full automatic integration, Flaresolverr must be installed, but alternatively, the firebase api key can be manually added to `login.json` and manually updated if/when it eventually changes (infrequently).

the current firebase api key is:
```json
    "firebase_api_key": "AIzaSyCIs7GZ0nqqzSdeZWxqYAw7FyGgbfM5GvM"
```
if Flaresolverr is used, the program defaults to using `http://localhost:8191/v1` but this can be overridden by adding a `flaresolverr_url` key in `login.json`.

# example
running the python script will print something like this:
```
===== Open Surveys =====
You have 2 open surveys.
Possible Earnings: $8.40
Total Time: 30 minutes

===== Balance =====
Current Balance: $29.39
Redeemable Balance: $25.00
Total Redeemed: $400.00
Total Earned: $429.39

===== Survey Stats =====
Completed: 88 (52.07%)
Screened Out: 63 (37.28%)
QA Flagged: 7 (4.14%)
Quota Exceeded: 11 (6.51%)
Active: 0 (0.00%)

===== Referral Stats =====
Total Referral Earnings: $47.00 from 2 referrals surveys.
People Referred:
 - John Smith: 21 surveys ($22.00) 
 - Leo Faber: 24 surveys ($25.00)  (Max referal bonus reached)
```

you can use the code for any project of course this just demonstrates that it actually works
