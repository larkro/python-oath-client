# python-oath-client
TOTP command line client in python

For storing and generating TOTP secrets and OTP:s for multiple accounts using sqlite and PBKDF2.


example

$ ./oath_client2.py -l
Accounts in db:
f7.storedsafe.com
github.com

$ ./oath_client2.py -o github.com
Please unlock the database
Password:
github.com : 797030
Valid for 23 more seconds.
