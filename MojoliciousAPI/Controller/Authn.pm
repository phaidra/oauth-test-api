package MojoliciousAPI::Controller::Authn;

use strict;
use warnings;
use v5.10;
use MIME::Base64 (qw/encode_base64 decode_base64/);
use Mojo::JSON qw(encode_json decode_json);
use Crypt::JWT qw(decode_jwt);
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
    scope => $self->app->config->{auth}->{oauth}->{scope},
    redirect_uri => $self->url_for("connect")->to_abs->scheme('https')
  });
  $self->app->log->info('authorizeurl: '.$url);
  $self->stash(authorizeurl => $url);
  $self->render;
}

sub logout {
  my $self = shift;

  $self->app->log->info("revoking token[".$self->session('access_token')."]");
  my $revokeurl = Mojo::URL->new;
  $revokeurl->scheme('https');
  $revokeurl->userinfo($self->app->config->{auth}->{oauth}->{client_id}.":".$self->app->config->{auth}->{oauth}->{client_secret});
  $revokeurl->host($self->app->config->{auth}->{oauth}->{authorization_server});
  $revokeurl->path("/revoke");
  my $result = $self->ua->post($revokeurl, form => {
      token           => $self->session('access_token'),
      token_type_hint => 'access_token'
      }
  )->result;
  if ($result->is_success) {
    $self->app->log->info("token revoked");
  } else {
    $self->app->log->error($result->code . " " . $result->message);
    $self->render(text => $result->code . " " . $result->message, status => 500);
    return;
  }

  $self->session(expires => 1);

  $self->app->log->info("redirecting to AS");

  my $redirecturl = Mojo::URL->new;
  $redirecturl->scheme('https');
  $redirecturl->host($self->app->config->{auth}->{oauth}->{authorization_server});
  $redirecturl->path("/endsession");
  $redirecturl->query({
    post_logout_redirect_uri => $self->app->config->{auth}->{oauth}->{logout_redirect_uri}
  });

  $self->redirect_to($redirecturl);
}

sub profile {
  my $self = shift;
  $self->stash(username => $self->session('username'));
  $self->stash(access_token => $self->session('access_token'));
  $self->render;
}

sub connect {
  my $self = shift;

  my $redirect_uri = $self->app->config->{auth}->{oauth}->{redirect_uri};
  my $get_token_args = {redirect_uri => $redirect_uri};

  $self->oauth2->get_token_p(oauthprovider => $get_token_args)->then(sub {
    my $provider_res = shift;
    $self->app->log->debug('provider res: '.$self->app->dumper($provider_res));
    return unless $provider_res;

    my $acctoken = $provider_res->{access_token};
    my $jwk = $self->app->config->{auth}->{oauth}->{jwk};

    # fetch key directly from AS if possible
    my $result = $self->ua->get("https://".$self->app->config->{auth}->{oauth}->{authorization_server}."/jwk")->result;
    $jwk = $result->json if $result->is_success;
    $self->app->log->info("keys: \n".$self->app->dumper($jwk));
    my $payload;
    eval {
      $payload = decode_jwt(token => $acctoken, kid_keys => $jwk, verify_iat => 1, verify_exp => 1);
    };
    if ($@) {
      $self->app->log->error("error decoding token: ".$self->app->dumper($@));
      return;
    }
    unless ($payload) {
      $self->app->log->error("error decoding token");
      return;
    }
    $self->app->log->info("payload: \n".$self->app->dumper($payload));

    # verify some other claims
    unless($payload->{iss} eq "https://".$self->app->config->{auth}->{oauth}->{authorization_server}."/") {
      $self->app->log->error('invalid iss['.$payload->{iss}.']');
      return;
    }
    unless($payload->{azp} eq $self->app->config->{auth}->{oauth}->{client_id}) {
      $self->app->log->error('invalid azp['.$payload->{azp}.']');
      return;
    }
   
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
