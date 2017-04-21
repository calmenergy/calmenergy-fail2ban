# Activate or define a fail2ban jail.
#
# All parameters are optional; providing any of them overrides the
# system-provided defaults in /etc/fail2ban/jail.conf;
# /etc/fail2ban/jail.local, /etc/fail2ban/fail2ban.conf, and /etc/fail2ban/fail2ban.local
#
# @example To activate a jail that is pre-configured in Fail2ban's jail.conf or jail.local
#  ::fail2ban::jail {'sshd':}
#
# @example To activate a pre-configured jail, altering one or more parameters
#   ::fail2ban::jail {'sshd':
#        bantime => 3600,
#   }
# @example To define a custom jail
#   ::fail2ban::jail {'myjail':
#        port   => 2718,
#        filter => 'myfilter',
#        log_path => '/var/log/myapp/log',
#        protocol => 'tcp',
#        maxretry => 4,
#        findtime => 300,
#        action   => '%(action_mw)s',
#        banaction => 'iptables-multiport',
#        bantime   => 360,
#        ignoreip  => ['172.24.8.0/24', 'localhost', 'myserver.com'],
#        backend   => 'auto',
#   }
#
# @param port  The port this jail should manage.
# @param filter The filter to use. Corresponds to a file in
#     /etc/fail2ban/filter.d/*.conf
# @param log_path an array of log files to examine for this jail, to detect
#     break-in attempts. (note the underlying option is 'logpath' but that
#     is a reserved metaparameter name in Puppet).
# @param ensure install or remove the jail.
# @param enabled enable or disable the jail.
# @param protocol the protocol to manage for this jail. 
# @param maxretry the number of tries, beyond which an error is considered a break-in attempt.
# @param findtime the number of seconds to look back to identify repeat tries.
# @param action A reference to one of the action templates defined in jail.conf or jail.local.
# @param banaction The ban action; a reference to a file in /etc/fail2ban/action.d/*.conf.
# @param bantime the number of seconds to ban a host.
# @param ignoreip Hosts to ignore when applying this jail
# @param order  Jails are applied in ascending order according to this parameter; Only for Debian < 7.
# @param backend The backend to use for this jail.
# @param comment An optional comment that will be inserted in the jail's config file.
define fail2ban::jail (
  Optional[Variant[String, Integer[1,6535]]] $port = undef,
  Optional[String]  $filter = undef,
  Optional[Variant[Stdlib::Absolutepath, Array[Stdlib::Absolutepath]]] $log_path = [],
  Enum['present', 'absent'] $ensure    = present,
  Boolean $enabled   = true,
  Optional[Enum['udp', 'tcp', 'icmp', 'all']] $protocol = undef,
  Optional[Integer] $maxretry  = undef,
  Optional[Integer] $findtime  = undef,
  Optional[String]  $action    = undef,
  Optional[String]  $banaction = undef,
  Optional[Integer] $bantime   = undef,
  Array[Variant[IP::Address::NoSubnet, IP::Address::V4::CIDR, String]] $ignoreip = [],
  Optional[Integer] $order     = undef,
  Optional[Enum['pyinotify', 'gamin', 'polling', 'systemd', 'auto']] $backend  = undef,
  Optional[String] $comment = '',
  ) {

  include ::fail2ban::config

  if type($log_path) =~ Type[String] {
    $log_path_array = [ $log_path ]
  } else {
    $log_path_array = $log_path
  }
  # Debian wheezy and older does not use jail.d
  if $::operatingsystem == 'Debian' and versioncmp($::operatingsystemrelease, '8') < 1 {
    if $ensure != present {
      notify {'no_ensure_wheezy':
        message => 'The $ensure parameter cannot be used on Debian 7 or older.',
      }
    }
    concat::fragment { "jail_${name}":
      target  => '/etc/fail2ban/jail.local',
      content => template("${module_name}/jail.erb"),
      order   => $order,
    }
  }
  else {
    if $order {
      notify {'order_only_with_wheezy':
        message => 'The parameter $order makes sense only with Debian 7 or older.',
      }
    }
    file { "/etc/fail2ban/jail.d/${name}.conf":
      ensure  => $ensure,
      content => template("${module_name}/jail.erb"),
      owner   => 'root',
      group   => $::fail2ban::config::root_group,
      mode    => '0644',
    }
  }
  }
