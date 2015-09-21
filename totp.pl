#!/usr/bin/perl -w
#
# 2 Factor Authentication Perl code which used the Time-based One-time Password
# Algorithm (TOTP) algorithm.  You can use this code with the Google Authenticator
# mobile app or the Authy mobile or browser app.
# See: http://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm
#
# To get this to work you:
#
# 1) Properly seed the random number generator.
# 2) Use generateBase32Secret(...) to generate a secret key for a user.
# 3) Store the secret key in the database associated with the user account.
# 4) Display the QR image URL returned by qrImageUrl(...) to the user.
# 5) User uses the image to load the secret key into his authenticator application.
#
# Whenever the user logs in:
#
# 1) The user enters the number from the authenticator application into the login form.
# 2) The server compares the user input with the output from generateCurrentNumber(...).
# 3) If they are equal then the user is allowed to log in.
#
# Thanks to Vijay Boyapati @ stackoverflow
# http://stackoverflow.com/questions/25534193/google-authenticator-implementation-in-perl
#
########################################################################################
#
# Copyright 2015, Gray Watson
#
# Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby
# granted provided that the above copyright notice and this permission notice appear in all copies.  THE SOFTWARE
# IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT,
# OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
# THIS SOFTWARE.
#
# By Gray Watson http://256.com/gray/
#

use strict;
use warnings;

use Digest::HMAC_SHA1 qw/ hmac_sha1_hex /;

# this is a standard for most authenticator applications
my $TIME_STEP = 30;

# there are better ways to seed the random number
srand(time() ^ $$);

# once we generate a secret, it can be associated with a user account and persisted
#my $base32Secret = generateBase32Secret();
# secret could have been retrieved from database associated with user
my $base32Secret = "NY4A5CPJZ46LXZCP";

print "secret = $base32Secret\n";

# this is the name of the key which can be displayed by the authenticator program
my $keyId = "user\@foo.com";
print "Image url = " . qrImageUrl($keyId, $base32Secret) . "\n";
# we can display this image to the user to let them load it into their auth program

# we can use the code here and compare it against user input
my $code = generateCurrentNumber($base32Secret);

#
# this little loop is here to show how the number changes over time
#
while (1) {
    my $diff = $TIME_STEP - (time() % $TIME_STEP);
    $code = generateCurrentNumber($base32Secret);
    print "Secret code = $code, change in $diff seconds\n";
    sleep(1);
}

#######################################################################################

#
# Generate a secret key in base32 format (A-Z2-7)
#
sub generateBase32Secret {
    my @chars = ("A".."Z", "2".."7");
    my $length = scalar(@chars);
    my $base32Secret = "";
    for (my $i = 0; $i < 16; $i++) {
	$base32Secret .= $chars[rand($length)];
    }
    return $base32Secret;
}

#
# Return the current number associated with base32 secret to be compared with user input.
#
sub generateCurrentNumber {
    my ($base32Secret) = @_;

    # For more details of this magic algorithm, see:
    # http://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm

    # need a 16 character hex value
    my $paddedTime = sprintf("%016x", int(time() / $TIME_STEP));
    # this starts with \0's
    my $data = pack('H*', $paddedTime);
    my $key = decodeBase32($base32Secret);

    # encrypt the data with the key and return the SHA1 of it in hex
    my $hmac = hmac_sha1_hex($data, $key);

    # take the 4 least significant bits (1 hex char) from the encrypted string as an offset
    my $offset = hex(substr($hmac, -1));
    # take the 4 bytes (8 hex chars) at the offset (* 2 for hex), and drop the high bit
    my $encrypted = hex(substr($hmac, $offset * 2, 8)) & 0x7fffffff;

    # the token is then the last 6 digits in the number
    my $token = $encrypted % 1000000;
    # make sure it is 0 prefixed
    return sprintf("%06d", $token);
}

#
# Return the QR image url thanks to Google.  This can be shown to the user and scanned
# by the authenticator program as an easy way to enter the secret.
#
sub qrImageUrl {
    my ($keyId, $base32Secret) = @_;
    my $otpUrl = "otpauth://totp/$keyId%3Fsecret%3D$base32Secret";
    return "https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl=200x200&chld=M|0&cht=qr&chl=$otpUrl";
}

#
# Decode a base32 number which is used to encode the secret.
#
sub decodeBase32 {
    my ($val) = @_;

    # turn into binary characters
    $val =~ tr|A-Z2-7|\0-\37|;
    # unpack into binary
    $val = unpack('B*', $val);

    # cut off the 000 prefix
    $val =~ s/000(.....)/$1/g;
    # trim off some characters if not 8 character aligned
    my $len = length($val);
    $val = substr($val, 0, $len & ~7) if $len & 7;

    # pack back up
    $val = pack('B*', $val);
    return $val;
}
