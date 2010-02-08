package HTML::FormHandler::Widget::Field::reCAPTCHA;

use Moose::Role;

sub render {
    my ( $self, $result ) = @_;
    $result ||= $self->result;

    if($self->validated) {
        my $security_salt = $self->security_salt->($self->parent->form, $self);
        return <<"END";
        <input type='hidden' name='recaptcha_response_field' value='$security_salt' />
        <input type='hidden' name='recaptcha_already_validated' value='1' />
END
    } else {        
        my @args = $self->prepare_public_recaptcha_args;
        my $output =  $self->recaptcha_instance->get_html(@args);
        return $self->wrap_field( $result, $output );
    }
}

use namespace::autoclean;
1;
