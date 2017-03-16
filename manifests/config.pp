# class fail2ban::config
# This class should not be included directly; use the main fail2ban class
class fail2ban::config {
  include ::fail2ban
  # These are for fail2ban.local:
  $log_level = $::fail2ban::log_level
  $logtarget = $::fail2ban::logtarget
  $syslogsocket = $::fail2ban::syslogsocket
  $socket = $::fail2ban::socket
  $pidfile = $::fail2ban::pidfile
  $dbfile = $::fail2ban::dbfile
  $dbpurgeage = $::fail2ban::dbpurgeage

  # These are for jail.local:
  $ignoreip = $::fail2ban::ignoreip
  $bantime = $::fail2ban::bantime
  $findtime = $::fail2ban::findtime
  $maxretry = $::fail2ban::maxretry
  $backend = $::fail2ban::backend
  $usedns = $::fail2ban::usedns
  $destemail = $::fail2ban::destemail
  $email_sender = $::fail2ban::email_sender
  $mta = $::fail2ban::mta
  $protocol = $::fail2ban::protocol
  $chain = $::fail2ban::chain
  $banaction = $::fail2ban::banaction
  $action = $::fail2ban::action

  # These are internal to the module
  $purge_jail_directory = $::fail2ban::purge_jail_directory
  $root_group = $::fail2ban::root_group


  file {'/etc/fail2ban/fail2ban.local':
    ensure  => file,
    owner   => 'root',
    group   => $root_group,
    mode    => '0400',
    content => template("${module_name}/fail2ban.local.erb"),
  }

  # Wheezy doesn't seem to support the jail.d pattern, so we
  # use jail.local concat::fragments
  if $::operatingsystem == 'Debian' and versioncmp($::operatingsystemrelease, '8') < 1 {
    if $purge_jail_directory  {
      notify {'wheezy_no_purge_jail':
        message => 'purging the jail directory on Debian 7 or older is not supported',

      }
    }
    concat { '/etc/fail2ban/jail.local':
      owner => 'root',
      group => $root_group,
      mode  => '0644',
    }
    concat::fragment { 'jail_header':
      target  => '/etc/fail2ban/jail.local',
      content => template("${module_name}/jail.local.erb"),
      order   => 1,
    }
  }
  # Not wheezy
  else {
    file { '/etc/fail2ban/jail.d':
      ensure  => directory,
      recurse => true,
      purge   => $purge_jail_directory,
      owner   => 'root',
      group   => $root_group,
      mode    => '0700',
    }
    file { '/etc/fail2ban/jail.local':
      ensure  => file,
      owner   => 'root',
      group   => $root_group,
      mode    => '0400',
      content => template("${module_name}/jail.local.erb"),
    }
  }

  # Create the firewall chain
  firewallchain {"${chain}:filter:IPv4":
    purge  => false,
  }

  firewall {'999 Return to INPUT':
    chain => $chain,
    jump  => 'RETURN',
  }

  firewall {'000 Check fail2ban':
    chain => 'INPUT',
    jump  => $chain,
  }
}
