package HTML::FormHandlerX::Field::reCAPTCHA;

use 5.008;
use Moose;
extends 'HTML::FormHandler::Field';

our $VERSION = '0.01';
our $AUTHORITY = 'cpan:JJNAPIORK';

has '+widget' => ( default => 'reCAPTCHA' );

has [qw/public_key private_key/] => (is=>'rw', isa=>'Str', required=>1);
has 'use_ssl' => (is=>'rw', isa=>'Bool', required=>1, default=>0);
has 'remote_address' => (is=>'rw', isa=>'Str', lazy_build=>1);
has 'recaptcha_options' => (is=>'rw', isa=>'HashRef', required=>1, default=>sub{ +{} });
has 'recaptcha_message' => (is=>'rw', isa=>'Str', default=>'Error validating reCAPTCHA');
has 'recaptcha_instance' => (is=>'ro', init_arg=>undef, lazy_build=>1);

sub _build_remote_address {
    $ENV{REMOTE_ADDR};
}

sub _build_input_param {
    return 'recaptcha_response_field';
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
    return unless $self->SUPER::validate;

    my @args = $self->prepare_private_recaptcha_args;
    my $result = $self->recaptcha_instance->check_answer(@args);
    if($result->{is_valid}) {
        return 1;
    } else {
        $self->add_error($self->recaptcha_message);
        return undef;
    }
}

=head1 NAME

HTML::FormHandler::Field::reCAPTCHA - Add a Captcha::reCAPTCHA field

=head1 SYNOPSIS

The following is example usage.

In your L<HTML::FormHandler> subclass:

    has_field 'recaptcha' => (
        type=>'reCAPTCHA', 
        public_key=>'[YOUR PUBLIC KEY]',
        private_key=>'[YOUR PRIVATE KEY]',
        required=>1,
    ); 

Example L<Catalyst> controller:

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
