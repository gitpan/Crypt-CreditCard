# $Revision: 1.10 $
# $Id: CreditCard.pm,v 1.10 2003/11/24 04:08:36 afoxson Exp $

# Crypt::CreditCard - 256-bit AES credit card encryption
# Copyright (c) 2003 Adam J. Foxson. All rights reserved.
# Copyright (c) 2003 Marty Pauley. All rights reserved.

# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.

package Crypt::CreditCard;

require 5.005;

use strict;
use Crypt::Rijndael;
use Crypt::Random qw(makerandom); 
use Digest::MD5 qw(md5);
use B; # lathos++
use vars qw($VERSION);

($VERSION) = ('$Revision: 1.10 $' =~ /\s+(\d+\.\d+)\s+/)[0] . '_01';

local $^W = 1;

sub new {
	my $type = shift;
	my $class = ref($type) || $type;
	my $self = {
		'_number' => undef,
		'_cvv2' => '',
		'_month' => '',
		'_year' => '',
		'_key' => undef,
		'_password' => undef,
		'_mode' => Crypt::Rijndael::MODE_CBC,
		'_strength' => 1,
		'_datasize' => 256,
		'_keylength' => 256,
		'_iv' => undef,
		'_errstr' => '',
	};

	return bless $self, $class;
}

sub mode {
	my $self = shift;

	if (@_) {
		my $mode = shift;
		if ($mode eq 'ecb') {
			$self->{_mode} = Crypt::Rijndael::MODE_ECB;
		}
		elsif ($mode eq 'cbc') {
			$self->{_mode} = Crypt::Rijndael::MODE_CBC;
		}
		elsif ($mode eq 'cfb') {
			$self->{_mode} = Crypt::Rijndael::MODE_CFB;
		}
		elsif ($mode eq 'ofb') {
			$self->{_mode} = Crypt::Rijndael::MODE_OFB;
		}
		elsif ($mode eq 'ctr') {
			$self->{_mode} = Crypt::Rijndael::MODE_CTR;
		}
		else {
			$self->errstr(__PACKAGE__ .
				": mode(): Invalid value for mode. Valid values are: " .
				"ecb, cbc, cfb, ofb, ctr");
			return 0;
		}
	}

	if ($self->{_mode} == Crypt::Rijndael::MODE_ECB) {
		return 'ecb';
	}
	elsif ($self->{_mode} == Crypt::Rijndael::MODE_CBC) {
		return 'cbc';
	}
	elsif ($self->{_mode} == Crypt::Rijndael::MODE_CFB) {
		return 'cfb';
	}
	elsif ($self->{_mode} == Crypt::Rijndael::MODE_OFB) {
		return 'ofb';
	}
	elsif ($self->{_mode} == Crypt::Rijndael::MODE_CTR) {
		return 'ctr';
	}
	else {
		$self->errstr(__PACKAGE__ .
			": mode(): Invalid value stored in mode. Valid values are: " .
			"ecb, cbc, cfb, ofb, ctr");
		return 0;
	}
}

sub errstr { 
	my $self = shift;
	$self->{_errstr} = shift if @_;
	return $self->{_errstr};
}

sub iv {
	my $self = shift;
	$self->{_iv} = shift if @_;
	return $self->{_iv};
}

sub strength {
	my $self = shift;

	if (@_) {
		my $strength = shift;
		if ($strength eq '/dev/random') {
			$self->{_strength} = 1;
		}
		elsif ($strength eq '/dev/urandom') {
			$self->{_strength} = 0;
		}
		elsif ($strength =~ m!^/dev/!) {
			$self->{_strength} = $strength;
		}
		else {
			$self->errstr(__PACKAGE__ .
				": strength(): Invalid value for strength. Valid values " .
				"are: /dev/random, /dev/urandom, or an alternate in /dev/");
			return 0;
		}
	}

	if ($self->{_strength} == 1) {
		return '/dev/random';
	}
	elsif ($self->{_strength} == 0) {
		return '/dev/urandom';
	}
	elsif ($self->{_strength} =~ m!^/dev/!) {
		return $self->{_strength};
	}
	else {
		$self->errstr(__PACKAGE__ .
			": strength(): Invalid value stored in strength. Valid values " .
			"are: /dev/random, /dev/urandom, or an alternate in /dev/");
		return 0;
	}
}

sub keylength {
	my $self = shift;
	if (@_) {
		my $number = shift;
		unless ($number == 256 or $number == 192 or $number == 128) {
			$self->errstr(__PACKAGE__ .
				": keylength(): Invalid value for keylength. Valid values " .
				"are: 256, 192, 128");
			return 0;
		}
		$self->{_keylength} = $number;
	}
	return $self->{_keylength};
}

sub datasize {
	my $self = shift;
	if (@_) {
		my $number = shift;
		unless ($number % 32 == 0) {
			$self->errstr(__PACKAGE__ .
				": datasize(): Invalid value for datasize. Datasize must " .
				"be a multiple of 32");
			return 0;
		}
		unless ($number >= 96) {
			$self->errstr(__PACKAGE__ .
				": datasize(): Invalid value for datasize. Datasize must " .
				"be >= 96");
			return 0;
		}
		$self->{_datasize} = $number;
	}
	return $self->{_datasize};
}

sub cvv2 {
	my $self = shift;
	if (@_) {
		my $cvv2 = shift;
		unless ($self->_is_string($cvv2)) {
			$self->errstr(__PACKAGE__ .  ": cvv2(): cvv2 must be a sting");
			return 0;
		}
		$self->{_cvv2} = $cvv2;
	}
	return $self->{_cvv2};
}

sub month {
	my $self = shift;
	if (@_) {
		my $month = shift;
		unless ($self->_is_string($month)) {
			$self->errstr(__PACKAGE__ .  ": month(): month must be a sting");
			return 0;
		}
		$self->{_month} = $month;
	}
	return $self->{_month};
}

sub year {
	my $self = shift;
	if (@_) {
		my $year = shift;
		unless ($self->_is_string($year)) {
			$self->errstr(__PACKAGE__ .  ": year(): year must be a sting");
			return 0;
		}
		$self->{_year} = $year;
	}
	return $self->{_year};
}

sub number {
	my $self = shift;
	my $args = @_;

	if ($args) {
		my $number = shift;
		unless ($self->_is_string($number)) {
			$self->errstr(__PACKAGE__ .  ": number(): number must be a sting");
			return 0;
		}
		unless ($self->_validate($number)) {
			$self->errstr(__PACKAGE__ .  ": number(): Invalid credit card " .
			"number");
			return 0;
		}
		$self->{_number} = $number;
	}
	else {
		unless ($self->_validate($self->{_number})) {
			$self->errstr(__PACKAGE__ .  ": number(): Invalid credit card " .
			"number");
			return 0;
		}
	}
	return $self->{_number};
}

sub _is_string {
	my ($self, $target) = @_;

	if (ref B::svref_2object(\$target) eq "B::PV") { # lathos++
		return 1;
	}
	else {
		return 0;
	}
}

sub key {
	my $self = shift;
	my $size = $self->{_keylength};

	if ($size == 256) {$size = 106}
	elsif ($size == 192) {$size = 79}
	elsif ($size == 128) {$size = 53}

	$self->{_key} = shift if @_;

	my $strength = $self->{_strength};

	if ($strength == 0 or $strength == 1) {
		$self->{_key} =
			"${\(makerandom(Size => $size, Strength => $strength))}" if
				not defined $self->{_key};
	}
	else {
		$self->{_key} =
			"${\(makerandom(Size => $size, Device => $strength))}" if
				not defined $self->{_key};
	}

	return $self->{_key};
}

sub password {
	my $self = shift;
	$self->{_password} = shift if @_;
	return $self->{_password};
}

sub _pack_cc {
	my $self = shift;
	my $datasize = $self->{_datasize} / 2 - 40;
	my $data = pack "A${datasize}NnA8A4A2A4", $self->_pad(),
		substr($self->{_number},0,8), int(rand(0xffff)),
		substr($self->{_number},8,8),
		$self->{_cvv2}, $self->{_month}, $self->{_year};

	return md5($data) . $data;
}

sub _unpack_cc {
	my $self = shift;
	my $data = shift;
	my $chk = substr $data, 0, 16, '';

	unless ($chk eq md5($data)) {
		$self->errstr(__PACKAGE__ .  ": Checksum check failed");
		return 0;
	}

	my $datasize = $self->{_datasize} / 2 - 40;
	my ($pad, $c1, $r, $c2, $cvv2, $month, $year) =
		unpack "A${datasize}NnA8A4A2A4", $data;

	return ("$c1$c2", $cvv2, $month, $year);
}

sub _pad {
	my $self = shift;
	my $rand;
	my $datasize = $self->{_datasize} / 2 - 40;

	for (1..$datasize) {$rand .= $self->_gen_pad()}

	return $rand;
}

sub encrypt {
	my $self = $_[0];

	if (not defined $self->{_key} or not defined $self->{_number} or
		not defined $self->{_password}) {
		$self->errstr(__PACKAGE__ .  ": encrypt(): Missing values for: " .
			"key, number, and/or password");
		return 0;
	}

	my $raw = $self->_pack_cc($self->{_number}, $self->{_cvv2},
		$self->{_month}, $self->{_year});
	my $key = unpack("H*", md5($self->{_password}) ^ pack("H*", $self->{_key}));
	my $cipher = Crypt::Rijndael->new($key, $self->{_mode});
	$cipher->set_iv($self->{_iv}) if defined $self->{_iv};
	my $ct = eval {$cipher->encrypt($raw)};

	if ($@) {
		$self->errstr(__PACKAGE__ .  ": encrypt(): $@");
		return 0;
	}

	$self->_kill($_[0]);
	$_[0] = {};

	unless ($ct) {
		$self->errstr(__PACKAGE__ .  ": encrypt(): Problem encrypting");
		return 0;
	}

	return unpack "H*", $ct;
}

sub _kill {
	delete $_[0]->{_number};
	delete $_[0]->{_cvv2};
	delete $_[0]->{_month};
	delete $_[0]->{_year};
	delete $_[0]->{_key};
	delete $_[0]->{_password};
	delete $_[0]->{_mode};
	delete $_[0]->{_strength};
	delete $_[0]->{_datasize};
	delete $_[0]->{_keylength};
	delete $_[0]->{_iv};
	delete $_[0]->{_errstr};
}

sub decrypt {
	my $self = shift;
	my $ciphertext = shift;

	if (not defined $self->{_key} or not defined $ciphertext or
		not defined $self->{_password}) {
		$self->errstr(__PACKAGE__ .  ": decrypt(): Missing values for: " .
			"key, ciphertext, and/or password");
		return 0;
	}

	my $key = unpack("H*", md5($self->{_password}) ^ pack("H*", $self->{_key}));
	my $cipher = Crypt::Rijndael->new($key, $self->{_mode});

	$cipher->set_iv($self->{_iv}) if defined $self->{_iv};

	my $raw = eval {$cipher->decrypt(pack "H*", $ciphertext)};

	if ($@) {
		$self->errstr(__PACKAGE__ .  ": decrypt(): $@");
		return 0;
	}

	unless ($raw) {
		$self->errstr(__PACKAGE__ .  ": decrypt(): Problem decrypting");
		return 0;
	}

	my ($c, $v, $m, $y) = $self->_unpack_cc($raw);

	if (not $c) {
		$self->errstr(__PACKAGE__ .  ": decrypt(): ${\($self->errstr())}");
		return 0;
	}

	$self->number($c);
	$self->cvv2($v);
	$self->month($m);
	$self->year($y);

	return 1;
}

# generate random crytographically secure alpha-padding
sub _gen_pad {
	my $self = shift;
	my %one = (
		0 => 'A', 1 => 'B', 2 => 'C', 3 => 'D', 4 => 'E',
		5 => 'F', 6 => 'G', 7 => 'H', 8 => 'I', 9 => 'J',
	);
	my %two = (
		0 => 'K', 1 => 'L', 2 => 'M', 3 => 'N', 4 => 'O',
		5 => 'P', 6 => 'Q', 7 => 'R', 8 => 'S', 9 => 'T',
	);
	my %three = (
		0 => 'U', 1 => 'V', 2 => 'W', 3 => 'X', 4 => 'Y',
		5 => 'Z', 6 => 'a', 7 => 'b', 8 => 'c', 9 => 'd',
	);
	my %four = (
		0 => 'e', 1 => 'f', 2 => 'g', 3 => 'h', 4 => 'i',
		5 => 'j', 6 => 'k', 7 => 'l', 8 => 'm', 9 => 'n',
	);
	my %five = (
		0 => 'o', 1 => 'p', 2 => 'q', 3 => 'r', 4 => 's',
		5 => 't', 6 => 'u', 7 => 'v', 8 => 'w', 9 => 'x',
	);

	my $rand = int(rand(5));
	my $key;
	my $strength = $self->{_strength};
	my $target;

	if ($strength == 0 or $strength == 1) {
		$key = makerandom(Size => 13, Strength => $strength);
	}
	else {
		$key = makerandom(Size => 13, Device => $strength);
	}

	if ($rand == 0) {$target = \%one}
	elsif ($rand == 1) {$target = \%two}
	elsif ($rand == 2) {$target = \%three}
	elsif ($rand == 3) {$target = \%four}
	else {$target = \%five}

	for my $num (keys %{$target}) {
		$key =~ s/$num/$target->{$num}/g;
	}

	return $key;
}

# derived from Business::CreditCard
sub _validate {
	my ($self, $number) = @_;
	my ($i, $sum, $weight);

	return 0 if $number !~ /^\d+$/;
	return 0 unless length($number) >= 13 && 0 + $number;
	return 0 unless length($number) >= 13 && length($number) <= 16;

	for ($i = 0; $i < length($number) - 1; $i++) {
		$weight = substr($number, -1 * ($i + 2), 1) * (2 - ($i % 2));
		$sum += (($weight < 10) ? $weight : ($weight - 9));
	}

	return 1 if substr($number, -1) == (10 - $sum % 10) % 10;
	return 0;
}

1;
