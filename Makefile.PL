use inc::Module::Install 0.91;
 
use warnings;
use strict;
 
all_from 'lib/HTML/FormHandlerX/Field/reCAPTCHA.pm';
repository 'git://github.com/jjn1056/Test-DBIx-Class.git'; 

requires 'HTML::FormHandler' => '0.30001';
test_requires 'Test::More' => '0.94';

auto_install;
tests_recursive;
WriteAll;
