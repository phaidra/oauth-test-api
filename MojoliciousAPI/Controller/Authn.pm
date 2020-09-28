package MojoliciousAPI::Controller::Authn;

use strict;
use warnings;
use v5.10;
use base 'Mojolicious::Controller';

sub authenticate {
  my $self = shift;

  unless($self->session('token')){
    $self->app->log->info("no session found");
    $self->render(text => 'not authenticated' , status => 401);
    return 0;
  }
  $self->app->log->info("token ".$self->session('token')." authenticated");
  return 1;
}

sub index {
  my $self = shift;
  $self->render;
}

sub logout {
  my $self = shift;
  $self->session(expires => 1);
}

sub profile {
  my $self = shift;
  $self->stash(token => $self->session->{token});
  $self->render;
}

sub connect {
  my $self = shift;

  my $get_token_args = {redirect_uri => $self->url_for("connect")->userinfo(undef)->to_abs};
 
  $self->oauth2->get_token_p(oauthprovider => $get_token_args)->then(sub {
    my $provider_res = shift;
    $self->app->log->info('provider res: '.$self->app->dumper($provider_res));
    return unless $provider_res;
    $self->session(token => $provider_res->{access_token});
    $self->redirect_to("profile");
  })->catch(sub {
    my $err = shift;
    $self->app->log->error($err);
    $self->render("connect", error => $err);
  });
}

1;
