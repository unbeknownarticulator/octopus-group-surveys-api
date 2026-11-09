import requests
import base64
import json
import os
import random
import re
import time
from collections import Counter, defaultdict
from collections.abc import Callable
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# curl_cffi can impersonate Chrome's TLS/HTTP2 fingerprint. Cloudflare's clearance cookie
# is often tied to that fingerprint, so plain `requests` gets rejected even after solving.
try:
    from curl_cffi import requests as cffi_requests
    from curl_cffi.requests import BrowserType
except ImportError:
    cffi_requests = None
    BrowserType = None

class OctopusAuth:
    def __init__(self, json_file: str):
        self.json_file = json_file

        # One shared session: browser-like headers + connection reuse
        self.impersonate = 'chrome'
        if cffi_requests is not None:
            self.session = cffi_requests.Session(impersonate=self.impersonate)
            # The impersonation profile supplies the user agent and sec-ch-ua headers.
            # Drop the two headers that only real page navigations send.
            self.session.headers.update({"Upgrade-Insecure-Requests": None, "Sec-Fetch-User": None})
        else:
            print("Note: curl_cffi isn't installed, so requests use Python's TLS fingerprint, which "
                  "Cloudflare may reject even after solving the challenge. Fix: pip install curl_cffi")
            self.session = requests.Session()
            self.session.headers["User-Agent"] = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"
            )

        # Headers Chrome sends on the site's own XHR/fetch calls
        self.session.headers.update({
            "Origin": "https://my.octopusgroup.com.au",
            "Referer": "https://my.octopusgroup.com.au/",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-AU,en;q=0.9",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
        })

        with open(self.json_file, 'r') as f:
            self.credentials = json.load(f)

        # Phone and password are guaranteed to be present
        phone_val = self.credentials['phone']
        self.phone = phone_val if phone_val[0] == '4' else phone_val[1:]
        self.password = self.credentials['password']

        # Cloudflare / FlareSolverr: reuse a previously solved session if we have one
        self.flaresolverr_url = self.credentials.get('flaresolverr_url') or 'http://localhost:8191/v1'
        self.cf_file = os.path.join(os.path.dirname(os.path.abspath(self.json_file)), 'cf_session.json')
        self._load_cf_session()

        # Handle optional credentials safely
        optional_keys = ['authorization', 'firebase_api_key', 'refresh_token']
        file_updated = False

        for key in optional_keys:
            if key in self.credentials and self.credentials[key] is not None:
                setattr(self, key, self.credentials[key])
            else:
                setattr(self, key, None)
                self.credentials[key] = ""
                file_updated = True

        if not self.firebase_api_key:
            api_key = self.regenerate_firebase_api_key()

            self.firebase_api_key = api_key
            self.credentials['firebase_api_key'] = api_key
            file_updated = True

        # Save back to the file only if missing keys were added/updated
        if file_updated:
            self._save_credentials()

        self.api_base = 'https://my.octopusgroup.com.au/api'

    # ------------------------------------------------------------------ helpers

    def _save_credentials(self):
        with open(self.json_file, 'w', encoding='utf-8') as f:
            json.dump(self.credentials, f, indent=4)

    # ------------------------------------------------------- Cloudflare handling

    def _apply_cf_session(self, user_agent: str, cookies: list):
        """Cloudflare's clearance cookie is tied to the user agent that solved
        the challenge, so we must adopt FlareSolverr's UA along with its cookies."""
        if user_agent:
            self.session.headers['User-Agent'] = user_agent
            if cffi_requests is not None:
                self.impersonate = self._pick_impersonation(user_agent)
                self.session.headers['sec-ch-ua-platform'] = self._platform_from_ua(user_agent)
        for c in cookies:
            self.session.cookies.set(c['name'], c['value'], domain=c.get('domain') or '', path=c.get('path', '/'))

    @staticmethod
    def _pick_impersonation(user_agent: str) -> str:
        """Use the TLS profile matching the user agent's Chrome version if curl_cffi has it."""
        m = re.search(r'Chrome/(\d+)', user_agent)
        if m and f'chrome{m.group(1)}' in {b.value for b in BrowserType}:
            return f'chrome{m.group(1)}'
        return 'chrome'

    @staticmethod
    def _platform_from_ua(user_agent: str) -> str:
        if 'Macintosh' in user_agent or 'Mac OS X' in user_agent:
            return '"macOS"'
        if 'Linux' in user_agent or 'X11' in user_agent:
            return '"Linux"'
        return '"Windows"'

    def _load_cf_session(self):
        try:
            with open(self.cf_file, 'r', encoding='utf-8') as f:
                saved = json.load(f)
            self._apply_cf_session(saved['userAgent'], saved['cookies'])
        except Exception:
            pass  # no saved session (or unreadable): we'll solve one if needed

    def _save_cf_session(self, user_agent: str, cookies: list):
        """Merge new cookies into the saved session instead of overwriting it.
        FlareSolverr returns no cookies for static files like main.js, and that must
        not wipe the clearance cookie saved from the page request."""
        if not cookies:
            return

        def key(c):
            return (c['name'], c.get('domain'), c.get('path'))

        merged = {}
        try:
            with open(self.cf_file, 'r', encoding='utf-8') as f:
                saved = json.load(f)
            # cookies are bound to the user agent that solved the challenge, so keep
            # the old ones only if it hasn't changed
            if saved.get('userAgent') == user_agent:
                merged = {key(c): c for c in saved['cookies']}
        except Exception:
            pass

        merged.update({key(c): c for c in cookies})

        with open(self.cf_file, 'w', encoding='utf-8') as f:
            json.dump({'userAgent': user_agent, 'cookies': list(merged.values())}, f, indent=4)

    @staticmethod
    def _is_cloudflare_challenge(response, url: str) -> bool:
        """True if this is a Cloudflare challenge page for our own site."""
        if response.status_code not in (403, 503):
            return False
        host = urlparse(url).hostname or ''
        if not host.endswith('octopusgroup.com.au'):
            return False
        if response.headers.get('cf-mitigated', '').lower() == 'challenge':
            return True
        body = response.text[:3000]
        return 'Just a moment' in body or 'challenge-platform' in body

    def _solve_cloudflare(self) -> bool:
        """Ask FlareSolverr to pass the challenge, then reuse its cookies + user agent
        in our normal session (FlareSolverr can't forward JSON POSTs or custom headers,
        so it's used only to obtain clearance, not to make the API calls)."""
        print("Cloudflare challenge detected. Solving via FlareSolverr...")

        try:
            # Plain requests.post, not self.session: FlareSolverr shouldn't get our cookies/headers
            r = requests.post(
                self.flaresolverr_url,
                json={"cmd": "request.get", "url": "https://my.octopusgroup.com.au/", "maxTimeout": 60000},
                timeout=90
            )
            data = r.json()
        except Exception as e:
            print(f"Could not reach FlareSolverr at {self.flaresolverr_url}: {e}")
            return False

        if data.get('status') != 'ok':
            print(f"FlareSolverr failed to solve the challenge: {data.get('message')}")
            return False

        solution = data['solution']
        self._apply_cf_session(solution['userAgent'], solution['cookies'])
        self._save_cf_session(solution['userAgent'], solution['cookies'])
        print("Cloudflare challenge solved.")
        return True

    def _send(self, method: str, url: str, **kwargs):
        """Single place all HTTP goes through: timeout, small random delay,
        Cloudflare challenge solving (once per request), and exponential
        backoff on 429/5xx (honouring Retry-After)."""
        kwargs.setdefault('timeout', 15)

        attempt = 0
        solved = False

        while True:
            time.sleep(random.uniform(0.4, 1.2))
            extra = {'impersonate': self.impersonate} if cffi_requests is not None else {}
            response = self.session.request(method, url, **kwargs, **extra)

            # Challenge page: solve once, then retry the same request
            if not solved and self._is_cloudflare_challenge(response, url):
                solved = True
                if self._solve_cloudflare():
                    continue
                return response

            if (response.status_code == 429 or response.status_code >= 500) and attempt < 2:
                try:
                    wait = float(response.headers.get('Retry-After', ''))
                except ValueError:
                    wait = 2 ** (attempt + 1) + random.uniform(0, 1)
                print(f"Got {response.status_code}, backing off {wait:.1f}s...")
                time.sleep(wait)
                attempt += 1
                continue

            return response

    # --------------------------------------------------------------- token logic

    def regenerate_authorization_token(self):
        """Exchange the refresh token for an authorization token."""
        url = "https://securetoken.googleapis.com/v1/token"

        try:
            response = self._send(
                'POST',
                url,
                params={"key": self.firebase_api_key},
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": self.refresh_token
                }
            )
        except Exception as e:
            print(f"An error occurred: {e}")
            return None

        if response.status_code != 200:
            return None

        return response.json().get("id_token")

    def _fetch_via_flaresolverr(self, url: str) -> str:
        """Fetch a page through FlareSolverr and return its body. Used for the
        Firebase key lookup, where we need clean page content, not API JSON."""
        try:
            r = requests.post(
                self.flaresolverr_url,
                json={"cmd": "request.get", "url": url, "maxTimeout": 60000},
                timeout=90
            )
            data = r.json()
        except Exception as e:
            raise RuntimeError(f"Could not reach FlareSolverr at {self.flaresolverr_url}: {e}")

        if data.get('status') != 'ok':
            raise RuntimeError(f"FlareSolverr failed for {url}: {data.get('message')}")

        solution = data['solution']
        # keep our normal session in sync with the freshest clearance
        self._apply_cf_session(solution['userAgent'], solution['cookies'])
        self._save_cf_session(solution['userAgent'], solution['cookies'])
        return solution['response']

    def regenerate_firebase_api_key(self):
        # get the main page html (via FlareSolverr) and parse for the main js file name
        html = self._fetch_via_flaresolverr('https://my.octopusgroup.com.au/')
        soup = BeautifulSoup(html, 'html.parser')

        main_js = None
        for script in soup.find_all("script"):
            src = script.get('src')
            if src and src.lstrip('/').startswith('main.'):
                main_js = src.lstrip('/')
                break

        if not main_js:
            raise RuntimeError("Could not find the main.js script tag on the site's main page.")

        # get the firebase api key from the main js file
        js_text = self._fetch_via_flaresolverr('https://my.octopusgroup.com.au/' + main_js)

        try:
            api_key = js_text.split('apiKey:"')[1].split('"')[0].strip()
        except IndexError:
            raise RuntimeError(f"Could not find the Firebase apiKey in {main_js}.")

        return api_key

    def get_authorization(self):
        """Get a valid authorization token, using saved refresh token or API login."""

        # Step A: Try saved refresh token
        auth_token = None
        if self.refresh_token and self.firebase_api_key:
            print("Found saved refresh token and Firebase API key. Generating authorization token via API...")
            auth_token = self.regenerate_authorization_token()

        if auth_token:
            self.authorization = auth_token
            self.credentials['authorization'] = auth_token
            self._save_credentials()
            return auth_token

        print("Saved refresh token expired, invalid, or missing. Falling back to API login...")

        # Step B: Use login API endpoint, and also get a new refresh token
        auth_token_request = self.post_request(
            '/Auth/Login',
            payload={
                'phoneNumber': '+61' + self.phone,
                'password': self.password
            },
            headers={'Referer': 'https://my.octopusgroup.com.au/' + 'login'},
            require_auth=False
        )

        if not auth_token_request:
            print("Failed to log in with given credentials. Check that you have entered the right phone number and password.")
            exit()

        auth_token = auth_token_request['token']

        # use the authorization token and the firebase api key to get refresh token
        refresh_token_request = self.post_request(
            f'https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key={self.firebase_api_key}',
            payload={
                "token": auth_token,
                "returnSecureToken": True
            },
            base='',
            require_auth=False
        )

        if not refresh_token_request:
            api_key = self.regenerate_firebase_api_key()

            self.firebase_api_key = api_key
            self.credentials['firebase_api_key'] = api_key
            self._save_credentials()

            refresh_token_request = self.post_request(
                f'https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key={self.firebase_api_key}',
                payload={
                    "token": auth_token,
                    "returnSecureToken": True
                },
                base='',
                require_auth=False
            )

        if not refresh_token_request:
            print("Failed to generate refresh token. The Firebase API key may be incorrect.")
            return None
        else:
            refresh_token = refresh_token_request['refreshToken']

        # 1. Update self.refresh_token first so the next function can see it
        self.refresh_token = refresh_token
        self.credentials['refresh_token'] = refresh_token

        # 2. Now generate the Firebase ID token using the new refresh token
        auth_token = self.regenerate_authorization_token()
        if not auth_token:
            print("Failed to generate Firebase ID token.")
            return None

        # 3. Save everything else
        self.authorization = auth_token
        self.credentials['authorization'] = auth_token

        print("Saved new refresh token and Firebase API key successfully!")

        self._save_credentials()

        return auth_token

    def _ensure_token(self) -> bool:
        """Refresh proactively if the token is missing or about to expire,
        so we don't generate a 401 on every run."""

        def token_expired(token: str, skew: int = 300) -> bool:
            """True if the JWT is missing, unreadable, or expires within `skew` seconds."""
            try:
                payload = token.split('.')[1]
                payload += '=' * (-len(payload) % 4)
                exp = json.loads(base64.urlsafe_b64decode(payload))['exp']
                return time.time() > (exp - skew)
            except Exception:
                return True
        
        if not self.authorization or token_expired(self.authorization):
            self.get_authorization()
        return bool(self.authorization)

    # ------------------------------------------------------------------ requests

    def _call(self, method: str, api_endpoint: str, headers: dict = None, payload: dict = None,
              _attempt: int = 0, base: str = None, require_auth: bool = True):

        if headers is None:
            headers = {}

        if require_auth:
            if not self._ensure_token():
                print("Could not obtain an authorization token.")
                return None
            headers['Authorization'] = 'Bearer ' + self.authorization

        try:
            if base is None:
                base = self.api_base

            kwargs = {'headers': headers}
            if method == 'POST':
                kwargs['json'] = payload

            response = self._send(method, base + api_endpoint, **kwargs)

            if response.status_code == 401:
                # Never retry unauthenticated calls (e.g. the login endpoint itself):
                # that is what causes repeated failed-login loops.
                if not require_auth or _attempt >= 2:
                    print(f"Unauthorized (401) on {api_endpoint}; not retrying.")
                    return None

                print("Received 401 Unauthorized. Token may have expired. Generating a new one...")
                self.get_authorization()
                return self._call(method, api_endpoint, headers, payload,
                                  _attempt + 1, base, require_auth)

            elif response.status_code in (200, 201):
                try:
                    return response.json()
                except ValueError:  # blank responses, bad syntax, etc.
                    return True

            else:
                print(f"Failed with status code: {response.status_code}")
                if response.status_code == 403:
                    print(
                        f"Access denied for {api_endpoint}. "
                        f"cf-mitigated={response.headers.get('cf-mitigated')!r}, "
                        f"server={response.headers.get('server')!r}"
                    )
                    print(f"Response starts with: {response.text[:200]!r}")
                elif response.status_code != 404:
                    print(response.text)
                return None

        except Exception as e:
            print(f"An error occurred: {e}")
            return None

    def get_request(self, api_endpoint: str, headers: dict = None, _attempt: int = 0,
                    base: str = None, require_auth: bool = True):
        return self._call('GET', api_endpoint, headers=headers, _attempt=_attempt,
                          base=base, require_auth=require_auth)

    def post_request(self, api_endpoint: str, headers: dict = None, payload: dict = None,
                     _attempt: int = 0, base: str = None, require_auth: bool = True):
        return self._call('POST', api_endpoint, headers=headers, payload=payload,
                          _attempt=_attempt, base=base, require_auth=require_auth)


class OctopusAPI:

    def __init__(self, json_file: str):
        self.json_file = json_file
        self.octopusauth = OctopusAuth(json_file)

        self.site = 'https://my.octopusgroup.com.au'

        self.api_member_details = "/Member/Details"
        self.api_open_surveys = "/Survey/OpenSurveys"
        self.api_get_redemptions = "/Redeem/GetRedemptions"
        self.api_redeem_setup_approval = '/Redeem/SetupApproval'
        self.api_redeem_check_for_approval = '/Redeem/CheckForApproval'
        self.api_redeem_cash = '/Redeem/RedeemCash'
        self.api_get_surveys = '/SurveyHistory/GetHistories'
        self.api_get_incentives = '/Incentive/GetIncentives'
        self.api_get_referals = '/Incentive/GetReferralIncentives'

        # The page the real site makes each call from
        self.referers = {
            self.api_member_details: f'{self.site}/',
            self.api_open_surveys: f'{self.site}/',
            self.api_get_redemptions: f'{self.site}/redeem',
            self.api_redeem_setup_approval: f'{self.site}/redeem',
            self.api_redeem_check_for_approval: f'{self.site}/redeem',
            self.api_redeem_cash: f'{self.site}/redeem',
            self.api_get_surveys: f'{self.site}/history',
            self.api_get_incentives: f'{self.site}/incentives',
            self.api_get_referals: f'{self.site}/profile#referral'
        }

    def _get(self, endpoint: str):
        return self.octopusauth.get_request(
            endpoint,
            headers={'Referer': self.referers[endpoint]}
        )

    def _post(self, endpoint: str, payload: dict):
        return self.octopusauth.post_request(
            endpoint,
            headers={'Referer': self.referers[endpoint]},
            payload=payload
        )

    def get_member_details(self):
        return self._get(self.api_member_details)

    def get_open_surveys(self):
        return self._get(self.api_open_surveys)

    def get_all_surveys(self):
        return self._post(self.api_get_surveys, {"PageNumber": 0, "PageSize": 1000})

    def get_incentive_history(self):
        return self._post(self.api_get_incentives, {"PageNumber": 0, "PageSize": 1000})

    def get_referals(self):
        return self._post(self.api_get_referals, {"PageNumber": 0, "PageSize": 1000})
    
    def get_redemptions(self):
        return self._post(self.api_get_redemptions, {"PageNumber": 0, "PageSize": 1000})

    def setup_redeem_approval(self, amount: int):
        return self._post(self.api_redeem_setup_approval, {"Amount": amount})
 
    def check_redeem_approval(self):
        return self._get(self.api_redeem_check_for_approval)
 
    def redeem_cash(self, bsb: str, account_number: str, amount: int):
        return self._post(self.api_redeem_cash, {
            "AccountBsb": bsb,
            "AccountNumber": account_number,
            "Amount": amount
        })


class Octopus:
    def __init__(self, json_file: str, auto_message_function: Callable[[], object] = None):
        self.auto_message = auto_message_function
        self.json_file = json_file
        self.octopusapi = OctopusAPI(json_file)

    def get_balance(self):
        return self.octopusapi.get_member_details()['points']

    def get_redeemable_balance(self, balance: float = None):
        if balance is None:
            balance = self.get_balance()
        return 0 if balance < 20 else int(balance // 5 * 5)

    def get_total_redeemed(self):
        redemptions = self.octopusapi.get_redemptions()

        total_redeemed = sum([r['amount'] for r in redemptions])
        return total_redeemed

    def get_total_earned(self, total_redeemed: float = None, balance: float = None):
        if total_redeemed is None:
            total_redeemed = self.get_total_redeemed()
        if balance is None:
            balance = self.get_balance()
        return total_redeemed + balance

    def get_open_surveys(self):
        open_surveys = self.octopusapi.get_open_surveys()

        if open_surveys is None:
            raise RuntimeError("Unable to retrieve open surveys; see the API error above.")

        survey_count = len(open_surveys)
        total_earnings = sum([s['incentive'] for s in open_surveys])
        total_time = sum([s['length'] for s in open_surveys])

        return {
            'number': survey_count,
            'total_earnings': total_earnings,
            'total_time': total_time
        }

    def survey_stats(self, surveys: list = None, active: int = None):
        if surveys is None:
            surveys = self.octopusapi.get_all_surveys()

        filtered_counts = defaultdict(int)

        for item in surveys:
            status: str = item['status']

            if status in {'Paused', 'Duplicate', 'Fresh', 'Active'}:
                continue

            if status.startswith('Complete'):
                filtered_counts['Complete'] += 1
            elif status.startswith('ScreenerFail'):
                filtered_counts['ScreenerFail'] += 1
            else:
                filtered_counts[status] += 1

        # Reuse the open-survey count if the caller already has it (saves an API call)
        if active is None:
            active = self.get_open_surveys()['number']
        filtered_counts['Active'] = active

        return dict(filtered_counts)
    
    def referal_stats(self, referals: list = None):
        if referals is None:
            referals = self.octopusapi.get_referals()
        

        total_referals = len(referals)
        total_earnings = sum([r['amount'] for r in referals])
        people_referred = Counter(item["description"].split("Member:")[-1].strip() for item in referals)

        return {
            'number': total_referals,
            'total_earnings': total_earnings,
            'people_referred': people_referred
        }

    
    @staticmethod
    def _is_approved(result) -> bool:
        if result is True:
            return True
        if isinstance(result, str):
            return result.strip().lower() == 'true'
        if isinstance(result, dict):
            return result.get('value') is True or result.get('approved') is True
        return False
 
    def redeem_cash(self, amount: int = None) -> bool:
        """Redeem cash to the bank account in the login file. Returns True on success."""
        if amount is not None:
            if amount < 20:
                print('Amount to redeem must be at least $20.')
                return False
            if amount % 5 != 0:
                print('Amount to redeem must be a multiple of 5.')
                return False
 
        # Bank details come from the login file
        credentials = self.octopusapi.octopusauth.credentials
        bsb = str(credentials.get('bsb') or '').strip()
        account_number = str(credentials.get('account_number') or '').strip()
 
        if not bsb or not account_number:
            print("Missing 'bsb' and/or 'account_number' in the login file. Add them to redeem cash.")
            return False
 
        redeemable = self.get_redeemable_balance()
 
        if amount is None:
            amount = redeemable
            if amount < 20:
                print('Redeemable balance is below $20.')
                return False
        elif amount > redeemable:
            print(f'Only ${redeemable} is redeemable right now.')
            return False
 
        # 1. Ask for approval
        print(f'Requesting approval to redeem ${amount}...')
        if self.octopusapi.setup_redeem_approval(amount) is None:
            print('Failed to set up approval. Redemption cancelled.')
            return False
 
        # 2. Notify the user (e.g. send the email/text) after a short pause
        time.sleep(2)
        if self.auto_message is not None:
            try:
                self.auto_message()
            except Exception as e:
                print(f'Error running auto message function: {e}')
        else:
            print('Not auto message function given. Manually approve the redemption.')
 
        # 3. Poll for approval
        print(f'Waiting for approval (checking every {15}s, up to {300 // 60} minutes)...')
        deadline = time.monotonic() + 300
        approved = False
 
        while time.monotonic() < deadline:
            if self._is_approved(self.octopusapi.check_redeem_approval()):
                approved = True
                break
            time.sleep(15)
 
        if not approved:
            print(f'Approval not received within {300 // 60} minutes. Redemption failed.')
            return False
 
        # 4. Redeem
        print('Approval confirmed. Redeeming...')
        time.sleep(2)
        if self.octopusapi.redeem_cash(bsb, account_number, amount) is None:
            print('RedeemCash request failed.')
            return False
 
        print(f'Redemption of ${amount} submitted successfully.')
        return True

if __name__ == '__main__':

    o = Octopus('login.json')

    try:
        open_surveys = o.get_open_surveys()
    except RuntimeError as error:
        raise SystemExit(str(error))

    balance = o.get_balance()
    total_redeemed = o.get_total_redeemed()
    total_earned = o.get_total_earned(balance=balance, total_redeemed=total_redeemed) # balance and total_redeemed parameters are optional but used here given balance and total_redeemed are already known to save 2 redundant API calls
    redeemable_balance = o.get_redeemable_balance(balance=balance) # balance parameter is again optional but used here to save a redundant API call
    survey_stats = o.survey_stats(active=open_surveys['number']) # active parameter optional as well
    referral_stats = o.referal_stats()

    print('===== Open Surveys =====')
    print(f"You have {open_surveys['number']} open survey{'' if open_surveys['number'] == 1 else 's'}.")
    print(f'Possible Earnings: ${open_surveys['total_earnings']:.2f}')
    print(f'Total Time: {open_surveys['total_time']} minute{'' if open_surveys['total_time'] == 1 else 's'}')

    print('\n===== Balance =====')
    print(f'Current Balance: ${balance:.2f}')
    print(f'Redeemable Balance: ${redeemable_balance:.2f}')
    print(f'Total Redeemed: ${total_redeemed:.2f}')
    print(f'Total Earned: ${total_earned:.2f}')

    total_counted_surveys = survey_stats.get('Complete', 0) + survey_stats.get('ScreenerFail', 0) + survey_stats.get('QA', 0) + survey_stats.get('QuotaFail', 0) + survey_stats.get('Active', 0)

    print('\n===== Survey Stats =====')
    if 'Complete' in survey_stats:
        print(f"Completed: {survey_stats['Complete']} ({survey_stats['Complete'] / total_counted_surveys * 100:.2f}%)")
    if 'ScreenerFail' in survey_stats:
        print(f"Screened Out: {survey_stats['ScreenerFail']} ({survey_stats['ScreenerFail'] / total_counted_surveys * 100:.2f}%)")
    if 'QA' in survey_stats:
        print(f"QA Flagged: {survey_stats['QA']} ({survey_stats['QA'] / total_counted_surveys * 100:.2f}%)")
    if 'QuotaFail' in survey_stats:
        print(f"Quota Exceeded: {survey_stats['QuotaFail']} ({survey_stats['QuotaFail'] / total_counted_surveys * 100:.2f}%)")
    if 'Active' in survey_stats:
        print(f"Active: {survey_stats['Active']} ({survey_stats['Active'] / total_counted_surveys * 100:.2f}%)")
        
    print('\n===== Referral Stats =====')
    print(f'Total Referral Earnings: ${referral_stats["total_earnings"]:.2f} from {referral_stats['number']} referral{'' if referral_stats['number'] == 1 else 's'} surveys.')
    if referral_stats['number'] > 0:
        print(f'People Referred:')
        for person, count in referral_stats['people_referred'].items():
            print(f' - {person}: {count} survey{"" if count == 1 else "s"} (${count + 1:.2f}) {"" if count < 24 else " (Max referal bonus reached)"}')