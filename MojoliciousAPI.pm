package MojoliciousAPI;

use strict;
use warnings;
use Mojo::Base 'Mojolicious';
use Log::Log4perl;
use Mojolicious::Plugin::OAuth2;

sub startup {
  my $self = shift;
  my $config = $self->plugin( 'JSONConfig' => { file => 'MojoliciousAPI.json' } );
  $self->config($config);
  $self->mode($config->{mode});
  $self->secrets([$config->{secret}]);
  push @{$self->static->paths} => 'public';

  Log::Log4perl::init('log4perl.conf');
  my $log = Log::Log4perl::get_logger("MojoliciousAPI");
  $self->log($log);

  if($config->{ssl_ca_path}) {
    $self->app->log->debug("Setting SSL_ca_path: ".$config->{ssl_ca_path});
    IO::Socket::SSL::set_defaults(
      SSL_ca_path => $config->{ssl_ca_path}
    );
  }

  $self->plugin("OAuth2" => {
    oauthprovider => $config->{authn}->{oauthprovider}
  });

  my $r = $self->routes;
  $r->namespaces(['MojoliciousAPI::Controller']);

  $r->route('/')                                                    ->via('get')    ->to('authn#index');
  $r->route('connect')                                              ->via('get')    ->to('authn#connect');
  $r->route('logout')                                               ->via('get')    ->to('authn#logout');

  my $check_auth = $r->under('/')->to('authn#authenticate');
  $check_auth->route('profile')                                     ->via('get')    ->to('authn#profile');


  return $self;
}

1;
