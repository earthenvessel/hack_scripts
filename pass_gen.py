#!/usr/bin/env python3
#
# pass_gen.py
#
# Password generator. Tries to balance memorizability and complexity.
#

from subprocess import run
from random import randrange,getrandbits,choice,shuffle
from os import access, R_OK
from os.path import isfile, expanduser
from pathlib import Path
import urllib.request

#
## 
### define variables ###
##
#
wordlist_url = 'https://raw.githubusercontent.com/first20hours/google-10000-english/master/google-10000-english-no-swears.txt'
directory = expanduser('~') + '/.evscripts'
wordlist = directory + '/google-10000-english-no-swears.txt'

min_pass_length = 14
max_pass_length = 20

min_word_length = 3
max_word_length = 12

min_words = 2
max_words = 4

min_digits = 1
max_digits = 2

min_symbols = 1
max_symbols = 2

grep_regex = '^[^#]{%i,%i}$' % (min_word_length, max_word_length)
symbols = list('~!@#$%^&*=+-_?/\\')
max_num = 100

password = ''

#
##
### functions ###
##
#

# rand_capitals function.
# takes a string as an argument. returns the
# string with a random, pre-defined capitalization
# scheme applied.
def rand_capitals(word):
    choice = randrange(1, 4)
    if choice == 1:   # leave lowercase
        return word
    elif choice == 2: # capitalize first letter
        return word.capitalize()
    elif choice == 3: # all uppercase
        return word.upper()

# check_criteria function.
# takes a password as an argument. determines whether the 
# password matches security criteria. returns True or False.
def check_criteria(pw):
    # Must be above min length
    if len(password) < min_pass_length:
        return False

    # Must be below max length
    if len(password) > max_pass_length:
        return False
    
    # Must have uppercase
    if password == password.lower():
        return False

    # Must have lowercase
    if password == password.upper():
        return False

    # Must have symbol
    if not any(char in symbols for char in password):
        return False

    # Must have digit
    if not any(char in ('0','1','2','3','4','5','6','7','8','9') for char in password):
        return False

    # Passed all checks
    return True

#
##
### main ###
##
#

# create directory for wordlist if doesn't exist
Path(directory).mkdir(exist_ok=True)

# download wordlist if needed
if not ( isfile(wordlist) and access(wordlist, R_OK) ):
    urllib.request.urlretrieve(wordlist_url, wordlist)

# create list of words that match the length criteria
grep_proc = run(
    ['grep', '-P', grep_regex, wordlist], 
    capture_output=True,
    encoding='ASCII',
    check=True
)
words = grep_proc.stdout.strip().split('\n')

# continue looping until password meets requirements
while(check_criteria(password) == False):

    # reset variables
    elements = []
    contains_non_words = True

    #
    ##
    ### build list of elements ###
    ##
    #

    # words
    for i in range(randrange(min_words, max_words + 1)):
        elements.append(rand_capitals(choice(words)))

    # mutate first word
    cut_letter = randrange(1, len(elements[0]) + 1)
    elements[0] = elements[0][0:cut_letter-1] + elements[0][cut_letter:]
    # confirm new word not in wordlist
    for w in words:
        if w.lower() == elements[0].lower():
            contains_non_words = False
            break
    if not contains_non_words:
        continue

    # symbols
    for i in range(randrange(min_symbols, max_symbols + 1)):
        elements.append(choice(symbols))

    # digits
    for i in range(randrange(min_digits, max_digits + 1)):
        elements.append(str(randrange(0, max_num)))

    # shuffle and assemble
    shuffle(elements)
    password = ''.join(elements)

# print final password
print(password)
