use Test;
use strict;
use Crypt::CreditCard;

BEGIN { plan tests => 353 };

for (1..100) {
	my $testcard = Crypt::CreditCard->new();
	$testcard->strength('/dev/urandom') || die $testcard->errstr();
	my $testkey = $testcard->key();
	ok(length($testkey) == 32);
}

for (1..100) {
	my $testcard = Crypt::CreditCard->new();
	$testcard->strength('/dev/urandom') || die $testcard->errstr();
	my $testpad = $testcard->_gen_pad();
	ok(length($testpad) == 4);
}

for (1..100) {
	my $testcard = Crypt::CreditCard->new();
	$testcard->strength('/dev/urandom') || die $testcard->errstr();
	my $testpad = $testcard->_pad();
	ok(length($testpad) == 352);
}

{
	my $testcard = Crypt::CreditCard->new();
	ok(ref $testcard eq 'Crypt::CreditCard');
}

{
	my $testcard = Crypt::CreditCard->new();
	my $iv = pack("H*", "000102030405060708090a0b0c0d0e0f");
	$testcard->iv($iv);
	ok($testcard->iv() eq $iv);
}

{
	my $testcard = Crypt::CreditCard->new();
	ok($testcard->mode() eq 'cbc');
	$testcard->mode('ecb') || die $testcard->errstr();
	ok($testcard->mode() eq 'ecb');
	$testcard->mode('cbc') || die $testcard->errstr();
	ok($testcard->mode() eq 'cbc');
	$testcard->mode('cfb') || die $testcard->errstr();
	ok($testcard->mode() eq 'cfb');
	$testcard->mode('ofb') || die $testcard->errstr();
	ok($testcard->mode() eq 'ofb');
	$testcard->mode('ctr') || die $testcard->errstr();
	ok($testcard->mode() eq 'ctr');
}

{
	my $testcard = Crypt::CreditCard->new();
	ok(not $testcard->_is_string(12345));
	ok($testcard->_is_string('12345'));
	ok($testcard->_is_string("12345"));
	ok(not $testcard->_is_string(9939393939));
	ok(not $testcard->_is_string(012));
	ok($testcard->_is_string('03939'));
}

{
	my $testcard = Crypt::CreditCard->new();
	ok($testcard->strength() eq '/dev/random');
	$testcard->strength('/dev/urandom') || die $testcard->errstr();
	ok($testcard->strength() eq '/dev/urandom');
	$testcard->strength('/dev/random') || die $testcard->errstr();
	ok($testcard->strength() eq '/dev/random');
}

{
	my $testcard = Crypt::CreditCard->new();
	ok($testcard->keylength() == 256);
	$testcard->keylength(128) || die $testcard->errstr();
	ok($testcard->keylength() == 128);
	$testcard->keylength(192) || die $testcard->errstr();
	ok($testcard->keylength() == 192);
	$testcard->keylength(256) || die $testcard->errstr();
	ok($testcard->keylength() == 256);
}

{
	my $testcard = Crypt::CreditCard->new();
	ok($testcard->datasize() == 256);
	$testcard->datasize(128) || die $testcard->errstr();
	ok($testcard->datasize() == 128);
	$testcard->datasize(192) || die $testcard->errstr();
	ok($testcard->datasize() == 192);
	$testcard->datasize(256) || die $testcard->errstr();
	ok($testcard->datasize() == 256);
}

{
	my $testcard = Crypt::CreditCard->new();
	ok(not $testcard->_validate('33333333333333333333'));
}

{
	my $testcard = Crypt::CreditCard->new();
	ok($testcard->_validate('5276440065421319'));
}

{
	my $testcard = Crypt::CreditCard->new();
	ok($testcard->_validate('4479358701841237'));
}

{
	my $testcard = Crypt::CreditCard->new();
	ok(not $testcard->_validate('abc'));
}

{
	my $testcard = Crypt::CreditCard->new();
	ok(not $testcard->_validate('333'));
}

{
	my $testcard = Crypt::CreditCard->new();
	ok(not $testcard->_validate('5276 4400 6542 1319'));
}

{
	my $card = Crypt::CreditCard->new();
	my $key = $card->key();
	my $number = '5276440065421319';
	my $cvv2 = '2345';
	my $month = '12';
	my $year = '03';
	my $password = 'foo';

	$card->strength('/dev/urandom') || die $card->errstr();
	$card->number($number) || die $card->errstr();
	$card->cvv2($cvv2) || die $card->errstr();
	$card->month($month) || die $card->errstr();
	$card->year($year) || die $card->errstr();
	$card->password($password);
	my $ciphertext = $card->encrypt() || die $card->errstr();
	ok(not defined $card->{_strength});
	ok(not defined $card->{_number});
	ok(not defined $card->{_password});
	ok(not defined $card->{_cvv2});
	ok(not defined $card->{_month});
	ok(not defined $card->{_year});
	ok(not defined $card->{_key});

	my $car = Crypt::CreditCard->new();
	$car->key($key);
	$car->password('foo');
	$car->decrypt($ciphertext) || die $car->errstr();

	ok($number, $car->number());
	ok($cvv2, $car->cvv2());
	ok($month, $car->month());
	ok($year, $car->year());
	ok($password, $car->password());
}

{
	my $card = Crypt::CreditCard->new();
	my $key = $card->key();
	my $number = '5276440065421319';
	my $password = 'bar';

	$card->strength('/dev/urandom') || die $card->errstr();
	$card->number($number) || die $card->errstr();
	$card->password($password);
	my $ciphertext = $card->encrypt() || die $card->errstr();
	ok(not defined $card->{_strength});
	ok(not defined $card->{_number});
	ok(not defined $card->{_password});
	ok(not defined $card->{_key});

	my $car = Crypt::CreditCard->new();
	$car->key($key);
	$car->password('bar');
	$car->decrypt($ciphertext) || die $car->errstr();

	ok($number, $car->number());
	ok($password, $car->password());
}

{
	my $testcard = Crypt::CreditCard->new();
	my $number = '5276440065421319';
	my $cvv2 = '0291';
	my $month = '05';
	my $year = '2004';

	$testcard->strength('/dev/urandom') || die $testcard->errstr();
	$testcard->number($number) || die $testcard->errstr();
	$testcard->cvv2($cvv2) || die $testcard->errstr();
	$testcard->month($month) || die $testcard->errstr();
	$testcard->year($year) || die $testcard->errstr();

	my $packed = $testcard->_pack_cc();
	my ($onumber, $ocvv2, $omonth, $oyear) = $testcard->_unpack_cc($packed);
	die $testcard->errstr() if not $onumber;

	ok($number, $onumber);
	ok($cvv2, $ocvv2);
	ok($month, $omonth);
	ok($year, $oyear);
}
