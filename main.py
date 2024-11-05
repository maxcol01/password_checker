import requests
import hashlib
import sys


def request_api_data(query_char: str) -> requests.models.Response: 
    """
    This  function calls the api to get the hashed password and number of times they were hacked
    """
    url = "https://api.pwnedpasswords.com/range/" + f"{query_char}"
    res = requests.get(url)
    if res.status_code != 200:
        raise RunTimeError(f"Error fetching: {res.status_code}, check the api and try again")  # type: ignore

    return res


def get_password_leaks_count(hashes: requests.models.Response, hash_to_check: requests.models.Response) -> int:
    """
    This function parses the api response and returns the count of times the hashed password was leaked
    """
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count 
    return 0



def pwned_api_check(password:str) -> int:
    """
    This function transform the password we enter into hashed version before passing it to the api call and the counts.
    """
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    head_hashed_password, tail_hashed_password = sha1password[:5], sha1password[5:]
    response = request_api_data(head_hashed_password)
    return get_password_leaks_count(response, tail_hashed_password)


def main(args: str) -> str:
    """
    This function loops over the password we want to check
    """
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f"{password} was hacked {count} times ... you should probably change your password.")
        else:
            print(f"{password} was not found in any data breaches. Good job!")
    return "ok"

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))