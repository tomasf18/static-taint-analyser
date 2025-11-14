#!/usr/bin/perl 
print "Give name to new file:\n"; # prints message to screen
$filename=<STDIN>; # assigns input to $filename

# $filename tainted
if ($filename =~ /^([-\@\w.]+)$/) { # match regular expression -> to make sure that the inputted value contains nothing but “word” characters (alphabetics, numerics, and underscores), a hyphen, an "at" sign, or a dot before opening the file.
    $filename = $1; # $filename here untainted
    open(FOO,"> $filename"); # opens file for output, handled by FOO
    print "Yay!"; # $filename untainted
} else {
    print "Boo!"; # $filename tainted
}