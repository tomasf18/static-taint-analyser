#!/usr/bin/perl 
print "Give name to new file:\n"; # prints message to screen
$filename=<STDIN>; # assigns input to $filename
open(FOO,"> $filename"); # opens file for output, handled by FOO
