package HTML::FormHandlerX::Widget::Field::reCAPTCHA;

use Moose::Role;

sub render {
    my ( $self, $result ) = @_;
    $result ||= $self->result;
    
    if( !$self->value || ($self->value && $self->has_errors)) {
        my @args = $self->prepare_public_recaptcha_args;
        my $err = $self->{recaptcha_error};
        my $output = $self->recaptcha_instance->get_html(@args, $err);
        return $self->wrap_field($result, $output);
    } else {        
        my $security_code = $self->security_code;
        return <<"END";
        <input type='hidden' name='recaptcha_response_field' value='$security_code' />
        <input type='hidden' name='recaptcha_already_validated' value='1' />
END
    }
}

use namespace::autoclean;
1;
