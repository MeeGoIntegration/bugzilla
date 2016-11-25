#!/usr/bin/perl -T
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# This Source Code Form is "Incompatible With Secondary Licenses", as
# defined by the Mozilla Public License, v. 2.0.

use 5.10.1;
use strict;
use warnings;

use lib qw(. lib);

use Bugzilla;
use Bugzilla::Constants;
use Bugzilla::Error;
use Bugzilla::Token;

use Authen::Captcha;

# Just in case someone already has an account, let them get the correct footer
# on an error message. The user is logged out just after the account is
# actually created.
my $user = Bugzilla->login(LOGIN_OPTIONAL);
my $cgi = Bugzilla->cgi;
my $template = Bugzilla->template;
my $vars = { doc_section => 'using/creating-an-account.html' };

print $cgi->header();

$user->check_account_creation_enabled;
my $login = $cgi->param('login');
# Added for Mer to pull uid from the params
my $uid = $cgi->param('uid');

# Modified for Mer to send uid to account creation and to put uid into
# the $vars for the templates. And added captcha for the robots

my $captcha_data = bz_locations()->{'datadir'} . "/captcha";
my $captcha_output = bz_locations()->{'assetsdir'};
my $captcha = Authen::Captcha->new(
    data_folder => $captcha_data,
    output_folder => $captcha_output,
);

if (defined($login)) {
    # Check the hash token to make sure this user actually submitted
    # the create account form.
    my $token = $cgi->param('token');
    check_hash_token($token, ['create_account']);

    my $captcha_token = $cgi->param('captcha_token');
    my $captcha_code = $cgi->param('captcha_code');
    my $result = $captcha->check_code($captcha_code, $captcha_token);
    if ($result == 0) {
        ThrowCodeError('captcha_check_error');
    } elsif ($result == -1) {
        ThrowUserError('captcha_expired');
    } elsif ($result < -1 ) {
        ThrowUserError('captcha_invalid');
    }

    $user->check_and_send_account_creation_confirmation($login, $uid);
    $vars->{'login'} = $login;
    $vars->{'uid'} = $uid;

    $template->process("account/created.html.tmpl", $vars)
      || ThrowTemplateError($template->error());
    exit;
}

$vars->{'captcha_token'} = $captcha->generate_code(10);

# Show the standard "would you like to create an account?" form.
$template->process("account/create.html.tmpl", $vars)
  || ThrowTemplateError($template->error());
