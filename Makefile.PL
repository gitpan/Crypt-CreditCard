use inc::Module::Install;

name('Crypt-CreditCard');
version_from('lib/Crypt/CreditCard.pm');
abstract('256-bit AES credit card encryption');
author('Adam J. Foxson <afoxson@pobox.com>');
license('gpl');
requires('Crypt::Rijndael' => '0.04');
requires('Crypt::Random' => '1.13');
requires('Digest::MD5' => '2.30');
include('ExtUtils::AutoInstall');
check_nmake();
auto_install();

&Meta->write;
&Build->write if lc($0) eq 'build.pl';
&Makefile->write if lc($0) eq 'makefile.pl';
