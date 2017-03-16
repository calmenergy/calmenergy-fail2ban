# fail2ban

#### Table of Contents

1. [Module Description - What the module does and why it is useful](#module-description)
1. [Setup - The basics of getting started with fail2ban](#setup)
     * [What fail2ban affects](#what-fail2ban-affects)
     * [Setup requirements](#setup-requirements)
     * [Beginning with fail2ban](#beginning-with-fail2ban)
1. [Usage - Configuration options and additional functionality](#usage)
1. [Reference - An under-the-hood peek at what fail2ban is doing and how](#reference)
1. [Limitations - OS compatibility, etc.](#limitations)
1. [Development - Guide for contributing to the module](#development)


## Module Description
The fail2ban module installs the [fail2ban](https://www.fail2ban.org) package, establishes local overrides to the distribution's config files, and configures and starts the fail2ban service.

It is designed to:
* Play nicely with the puppetlabs firewall module, by not creating firewall rules that the firewall module will then purge.
* Work well with the profile/roles pattern:
  * declaring the base class sets up and runs fail2ban, but does not activate any jails.
  * a profile that manages a particular service (e.g., sshd, apache) can also manage the jail associated with that service

As recommended by fail2ban's authors, this module makes no changes to the underlying fail2ban dstribution,
instead using local overrides for configuration.

It works with Debian 7 or 8, RedHat 6 and 7, and CentOS 6 and 7. It requires puppet version 4.9.0 or newer, or Puppet Enterprise 2017.1 or newer.

## Setup

### What fail2ban affects
Other than the files associated with the fail2ban package itself, the fail2ban module creates a firewall chain (default name FAIL2BAN) and 
adds a jump to it at the beginning of the INPUT firewall chain.

### Setup Requirements
This module itself has no special setup requirements.
The fail2ban package imposes its own requirements. In particular, it needs access to a firewall system (typically iptables), and to the logfiles of any process it is instructed to monitor.

Note that if Puppet is managing fail2ban and the iptables firewall, and if fail2ban is configured to add rules to the INPUT chain,  
puppet will see the rules that fail2ban has added as being unmanaged, and so Puppet will, by default, purge them. This module addresses 
that problem by creating a separate iptables chain (default name 'FAIL2BAN'), managing rules only in that chain, and adding to the beginning
of the INPUT chain a jump to the FAIL2BAN chain. 

### Beginning with fail2ban

For a basic installation just declare or include the `fail2ban` class

```puppet
   class {'::fail2ban':}
```

or 

```puppet
   include ::fail2ban
```

The basic installation includes no jails. Jails can be activated by declaring `fail2ban::jail` resources.

```puppet
  ::fail2ban::jail{'sshd':}
```

## Usage

### Stock installation

* For a stock installation, just declare the fail2ban class, and declare a fail2ban::jail resource for every jail you wish to activate

### Overriding default parameters
Use Hiera to provide alternatives to the default values for the fail2ban class


### Activating built-in jails
To activate a built-in jail, using default parameters:

```puppet
  ::fail2ban::jail {'sshd':}
```

To activate a built-in jail, modifying one or more parameters:

```puppet
   ::fail2ban::jail {'sshd':
        bantime => 3600,
   }
```

### Defining custom jails

```puppet
   ::fail2ban::jail {'myjail':
        port   => 2718,
        filter => 'myfilter',
        log_path => '/var/log/myapp/log',
        protocol => 'tcp',
        maxretry => 4,
        findtime => 300,
        action   => '%(action_mw)s',
        banaction => 'iptables-multiport',
        bantime   => 360,
        ignoreip  => ['172.24.8.0/24', 'localhost', 'myserver.com'],
        backend   => 'auto',
   }
```

### Defining custom filters

```puppet
  ::fail2ban::filter{'myfilter':
     failregexes => ['^%(_apache_error_client)s (AH01789: )?(Digest: )?unknown algorithm `.*?' received: \S*(, referer: \S+)?\s*$'],
     ensure => present,
     ignoreregexes => ['bogus_error', 'just_kidding'],
     includes_before => ['myincludefile.conf', 'otherincludefile.conf'],
     includes_after  => ['cleanupfile.conf'],
     additional_defs   => ['foo = 2718', 'entropy_seed = 2917384297'],
   }
```

## Reference

All classes, types, and associated parameters are documented via puppet-strings.


## Requirements

This module depends on:

 * [puppetlabs-stdlib](https://forge.puppetlabs.com/puppetlabs/std) (at least version 4.13.0)
 * [puppetlabs-concat](https://forge.puppetlabs.com/puppetlabs/concat) (at least version 2.2.0)
 * [puppetlabs-firewall](https://forge.puppetlabs.com/puppetlabs/firewall) (at least version 1.8.2)
 * [thrnio-ip](https://forge.puppetlabs.com/thrnio/ip) (at least version 1.0.0)

## Compatibility

This module supports

 * Debian 7 and 8
 * RHEL 6 and 7
 * CentOs 6 and 7


## Development

Contributions and pull requests are welcome.

## Contributors

https://github.com/calmenergy/calmenergy-fail2ban/graphs/contributors

## Release Notes/Etc

See the CHANGELOG.md for release notes.

