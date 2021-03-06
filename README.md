2 Factor Authentication (2FA) Perl code which used the Time-based One-time Password
Algorithm (TOTP) algorithm.  You can use this code with the Google Authenticator
mobile app or the Authy mobile or browser app.

See: http://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm

To get this to work you:

 1. Properly seed the random number generator.
 2. Use generateBase32Secret(...) to generate a secret key for a user.
 3. Store the secret key in the database associated with the user account.
 4. Display the QR image URL returned by qrImageUrl(...) to the user.
 5. User uses the image to load the secret key into his authenticator application.

Whenever the user logs in:

1. The user enters the number from the authenticator application into the login form.
2. Server looks up the secret associated with the user in the database.
3. The server compares the user input with the output from generateCurrentNumber(...).
4. If they are equal then the user is allowed to log in.

Thanks to Vijay Boyapati @ stackoverflow for initial code.

http://stackoverflow.com/questions/25534193/google-authenticator-implementation-in-perl

NOTE: this script depends on Digest::HMAC_SHA1
