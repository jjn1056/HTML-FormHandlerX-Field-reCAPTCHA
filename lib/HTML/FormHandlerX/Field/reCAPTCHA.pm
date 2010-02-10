package HTML::FormHandlerX::Field::reCAPTCHA;

use 5.008;
use Captcha::reCAPTCHA;
use Crypt::CBC;

use Moose;
extends 'HTML::FormHandler::Field';

our $VERSION = '0.01';
our $AUTHORITY = 'cpan:JJNAPIORK';

has '+widget' => ( default => 'reCAPTCHA' );
has '+input_param' => ( default => 'recaptcha_response_field' );

has [qw/public_key private_key/] => (is=>'rw', isa=>'Str', required=>1);
has 'use_ssl' => (is=>'rw', isa=>'Bool', required=>1, default=>0);
has 'remote_address' => (is=>'rw', isa=>'Str', lazy_build=>1);
has 'recaptcha_options' => (is=>'rw', isa=>'HashRef', required=>1, default=>sub{ +{} });
has 'recaptcha_message' => (is=>'rw', isa=>'Str', default=>'Error validating reCAPTCHA');
has 'recaptcha_instance' => (is=>'ro', init_arg=>undef, lazy_build=>1);
has 'encrypter' => (is=>'ro', init_arg=>undef, lazy_build=>1,
  handles=>[qw/encrypt_hex decrypt_hex/]);

sub _build_encrypter {
    my $self = shift @_;
    my $key = pack("H16",$self->private_key);
    return Crypt::CBC->new(-key=>$key,-cipher=>"Blowfish");   
}

sub _build_remote_address {
    $ENV{REMOTE_ADDR};
}

sub _build_recaptcha_instance {
    Captcha::reCAPTCHA->new();
}

sub prepare_private_recaptcha_args {
    my $self = shift @_;
    return (
        $self->private_key,
        $self->prepare_recaptcha_args,
    );
}

sub prepare_public_recaptcha_args {
    my $self = shift @_;
    return (
        $self->public_key,
        $self->prepare_recaptcha_args,
    );
}

sub prepare_recaptcha_args {
    my $self = shift @_;
    return (
        $self->remote_address,
        $self->form->params->{'recaptcha_challenge_field'},
        $self->form->params->{'recaptcha_response_field'},
    );
}

sub validate {
    my ($self, @rest) = @_;
    unless(my $super = $self->SUPER::validate) {
        return $super;
    }
    my $recaptcha_response_field = $self->form->params->{'recaptcha_response_field'};
    if($self->form->params->{'recaptcha_already_validated'}) {
        if($recaptcha_response_field &&
          ($self->decrypt_hex($recaptcha_response_field) eq $self->public_key)
        ) { 
            return 1;
        } else {
            $self->add_error("Previous reCAPTCHA validation lost.");
            return undef;
        }
    } else {
        my @args = $self->prepare_private_recaptcha_args;
        my $result = $self->recaptcha_instance->check_answer(@args);
        if($result->{is_valid}) {
            return 1;
        } else {
            $self->{recaptcha_error} = $result->{error};
            $self->add_error($self->recaptcha_message);
            return undef;
        }
    }
}

=head1 NAME

HTML::FormHandler::Field::reCAPTCHA - Add a Captcha::reCAPTCHA field

=head1 SYNOPSIS

The following is example usage.

In your L<HTML::FormHandler> subclass:

    has 'valid_recaptcha_security_code' => (
        is=>'rw',
        required=>1,
    );

    has_field 'recaptcha' => (
        type=>'reCAPTCHA', 
        public_key=>'[YOUR PUBLIC KEY]',
        private_key=>'[YOUR PRIVATE KEY]',
        required=>1,
    ); 

Example L<Catalyst> controller:

    ## Probably not the most secure code :)
    my $form = MyApp::HTML::Forms::MyForm->new(
      valid_recaptcha_security_code=>$c->session_id,
    );

    my $params = $c->request->body_parameters;
    if(my $result = $form->process(params=>$params) {
        ## The Form is totally valid. Go ahead with whatever is next.
    } else {
        ## Invalid results, you need to display errors and try again.
    }

=head1 DESCRIPTION

Uses L<Captcha::reCAPTCHA> to add a "Check if the agent is human" field.  You 
will need an account from http://recaptcha.net/ to make this work.

=head1 FIELD OPTIONS

We support the following additional field options, over what is inherited from
L<HTML::FormHandler::Field>

=head2 public_key

The public key you get when you create an account on http://recaptcha.net/

=head2 private_key

The private key you get when you create an account on http://recaptcha.net/

=head1 FORM ATTRIBUTES

We support the following form attributes

=head2 valid_recaptcha_security_code

Expects a value.  The idea here is that if your client validates the reCAPTCHA
but makes some other error, you don't want to keep displaying the reCAPTCHA.  So
the first time a form validates the reCAPTCHA we replace it with a hidden field
whose value is a secure code you can control.

=head1 SEE ALSO

The following modules or resources may be of interest.

L<HTML::FormHandler>, L<Captch::reCAPTCHA>

=head1 AUTHOR

John Napiorkowski C<< <jjnapiork@cpan.org> >>

=head1 COPYRIGHT & LICENSE

Copyright 2010, John Napiorkowski C<< <jjnapiork@cpan.org> >>

Original work sponsered by Shutterstock, LLC. 
<<a href="http://shutterstock.com/">http://shutterstock.com</a>>

This program is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

__PACKAGE__->meta->make_immutable;
use namespace::autoclean;
1;
