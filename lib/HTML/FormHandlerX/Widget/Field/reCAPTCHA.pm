package HTML::FormHandlerX::Widget::Field::reCAPTCHA;

use Moose::Role;

sub render {
    my ( $self, $result ) = @_;
    $result ||= $self->result;
    
    my @args = $self->prepare_public_recaptcha_args;
    my $output =  $self->recaptcha_instance->get_html(@args);
    return $self->wrap_field( $result, $output );
}

use namespace::autoclean;
1;
