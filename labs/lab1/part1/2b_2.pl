#!/usr/bin/perl
print "Give name to new file:\n"; 
$filename = <STDIN>;

# validate and untaint filename: allow only letters, digits, dot, underscore and hyphen
# this prevents directory traversal and other unsafe characters
if ($filename =~ /^([A-Za-z0-9._-]+)$/) { # match safe filename characters
    $filename = $1; # $filename here untainted
    print "Yay!\n"; # $filename untainted
    open(FOO,"> $filename"); # opens file for output, handled by FOO
} else {
    print "Boo!\n"; # $filename tainted
    die "Invalid filename: only A-Z a-z 0-9 . _ - are allowed\n";
}

