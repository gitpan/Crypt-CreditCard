#!/usr/bin/perl -w

use strict;
print "1..1\n";

if (!eval { require Socket; Socket::inet_aton('pgp.mit.edu') }) {
	print "ok 1 # skip - Cannot connect to the keyserver\n";
}
elsif (!eval { require Module::Signature; 1 }) {
	warn "\n# Next time around, consider installing Module::Signature, ".
	"so that you can\n# verify the integrity of this distribution.\n";
	print "ok 1 # skip - Module::Signature not installed\n";
}
else {
	(Module::Signature::verify() == Module::Signature::SIGNATURE_OK())
	or print "not ";
	print "ok 1 # Valid signature\n";
}
