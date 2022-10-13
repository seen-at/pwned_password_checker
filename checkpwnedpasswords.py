# to make request to websites like browsers
import requests

# to convert the password entered to SHA1 code
import hashlib
import sys

# function to receive api data with parameter of first 5 characters of converted password
def request_api_data(query_char):
    # 'pwnedpasswords' website API to check password stored in the variable
    # the password(first five hashed characters) to be checked is added to the 'url' variable
    # first 5 characters of hashed key is checked
    url = 'https://api.pwnedpasswords.com/range/' + query_char

    # the response from the 'url' is obtained and stored in the variable
    # all the passwords with matching first5_char from the API request are received
    res = requests.get(url)
    # print(res) gives 'Response [400]' for unhashed password given indicating error
    # values over 200 indicate malfunction
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again.')
    return res

# function to convert the actual password by hash algorithm
def pwned_api_check(password):
    # password encoded to 'utf-8' to be converted to hash
    # 'hashlib.sha1()' takes encoded password to be converted using SHA1 algorithm, giving an object
    # hexdigest converts the object into a hexadecimal string of lower case
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

    # storing the first 5 characters and the remaining part of the password in variables
    first5_char, tail = sha1password[:5], sha1password[5:]

    # pwnedpassword API requested here with the function and the argument fed in to be first5_char
    # gives the response value from the server
    response = request_api_data(first5_char)

    # function 'read_response' called to read the response values from the server
    # return read_response(response)

    # function 'get_password_leaks_count' receives the response object which contains all the matched passwords and leaked times
    # tail is the
    return get_password_leaks_count(response, tail)


# all the passwords with matching first5_char returned by the function
# the number of times the passwords have been hacked is shown after a colon
# def read_response(response):
#    print(response.text)

# function to get hashed passwords and the number of times each were hacked to be given without the colon
# the parameter 'hashes' is the 'response' received in the 'pwned_api_check' function
# the parameter 'hashes_to_check' is the tail of the password minus the firt5_char needed to find match with the response
def get_password_leaks_count(hashes, hashes_to_check):
    # separates the tail and the colon
    # 'hashes.text()' returns all the matching ends of the password with leak counts similar to 'read_response' function
    # the variable 'line' stores the matched ends and the count of leaks as string
    # 'splitlines()' takes the strings and returns them in a list as items breaking at boundaries
    # without the method, it loops over all the individual letters of the string
    hashes = (line.split(':') for line in hashes.text.splitlines())

    # 'h' and 'count' stores the tails with the matching first5_char and the number of leaks respectively
    for h, count in hashes:
        # the tail of the hashed password input is compared with all the other tails received from the 'response'
        # the number of times the password has been leaked is returned
        if h == hashes_to_check:
            return count
    return 0

# function to receive multiple arguments as passwords
def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was find {count} times. Needs to be changed')
        else:
            print(f'{password} was not found.')
    return 'done!'

if __name__ == '__main__':
    # this will be run and exited to the command line returning 'done!'
    sys.exit(main(sys.argv[1:]))

# pwned_api_check('arg') converts the argument using hash algorithm
# the first5_char is then taken and sent to the function 'request_api_data()' which adds them to the 'pwnedpasswordchecker' website URL
# responses are obtained from the URL are returned and stored in the variable 'response' within 'pwned_api_check'
# 'get_password_leaks_count()' function takes the response and tail of the hashed password which hasn't been sent
# 'response' contains the tails of password matching with the 'first5_char'
# 'get_password_leaks_count()' function loops through all the hashed tails to check for a match
# the number of leaks is returned ultimately by the 'pwned_api_check' function
