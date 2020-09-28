package MojoliciousAPI::Controller::Authn;

use strict;
use warnings;
use v5.10;
use MIME::Base64 (qw/encode_base64 decode_base64/);
use Mojo::JSON qw(encode_json decode_json);
use base 'Mojolicious::Controller';

sub authenticate {
  my $self = shift;

  unless($self->session('username')){
    $self->app->log->info("no session found");
    $self->render(text => 'not authenticated' , status => 401);
    return 0;
  }
  $self->app->log->info("username ".$self->session('username')." authenticated");
  return 1;
}

sub index {
  my $self = shift;
  my $url = $self->oauth2->auth_url("oauthprovider", {
    scope => $self->app->config->{authn}->{oauth}->{scope},
    redirect_uri => $self->url_for("connect")->to_abs->scheme('https')
  });
  $self->app->log->info('authorizeurl: '.$url);
  $self->stash(authorizeurl => $url);
  $self->render;
}

sub logout {
  my $self = shift;
  $self->session(expires => 1);
  $self->redirect_to("https://".$self->app->config->{authn}->{oauth}->{authorization_server}."/");
}

sub profile {
  my $self = shift;
  $self->stash(username => $self->session('username'));
  $self->stash(access_token => $self->session('access_token'));
  $self->render;
}

sub connect {
  my $self = shift;

  my $redirect_uri = $self->url_for("connect")->userinfo(undef)->to_abs->scheme('https');
  my $get_token_args = {redirect_uri => $redirect_uri};

  $self->oauth2->get_token_p(oauthprovider => $get_token_args)->then(sub {
    my $provider_res = shift;
    $self->app->log->debug('provider res: '.$self->app->dumper($provider_res));
    return unless $provider_res;

    # get id token data
    my $idtoken = $provider_res->{id_token};
    my @arr = split(/\./, $idtoken);
    my $payload = decode_json(decode_base64($arr[1]));
    $self->app->log->debug('idtoken payload: '.$self->app->dumper($payload));

    # verify claims
    unless($payload->{iss} eq "https://".$self->app->config->{authn}->{oauth}->{authorization_server}."/") {
      $self->app->log->error('invalid iss['.$payload->{iss}.']');
      return;
    }
    unless($payload->{aud} eq $self->app->config->{authn}->{oauth}->{client_id}) {
      $self->app->log->error('invalid aud['.$payload->{iss}.']');
      return;
    }
    my $now = time();
    unless($payload->{exp} > $now) {
      $self->app->log->error('invalid exp['.$payload->{exp}.'] now['.$now.']');
      return;
    }

    # TODO verify signature

    # create session
    my $username = $payload->{sub};
    $self->session(access_token => $provider_res->{access_token});
    $self->session(username => $username);
    $self->redirect_to("profile");
  })->catch(sub {
    my $err = shift;
    $self->app->log->error($err);
    $self->render(text => $err, status => 403);
  });
}

1;
