# Configure a filter for fail2ban.
#
# Creates a file /etc/fail2ban/filter.d/<name>.conf to configure the filter, which
# can subsequently be referenced by a jail's configuration.
# @example to define a filter
#  ::fail2ban::filter{'myfilter':
#     failregexes => ['^%(_apache_error_client)s (AH01789: )?(Digest: )?unknown algorithm `.*?' received: \S*(, referer: \S+)?\s*$'],
#     ensure => present,
#     ignoreregexes => ['bogus_error', 'just_kidding'],
#     includes_before => ['myincludefile.conf', 'otherincludefile.conf'],
#     includes_after  => ['cleanupfile.conf'],
#     additional_defs   => ['foo = 2718', 'entropy_seed = 2917384297'],
#   }
#
# @param ensure Whether to add or remove this filter. 
# @param failregexes An array of regexes to match against lines in the log file. Successful match indicates a potential break-in attempt.
# @param ignoreregexes An array of regexes to match against lines in the log file. Lines matching any of these regexes are ignored.
# @param includes_before An array of files to include prior to the main definition of this filter.
# @param includes_after An array of files to include after the main definition of this filter.
# @param additional_defs An array of additional definition lines to include in this filter's config file. 
# @param comment An optional comment that will be inserted in the filter's config file.
define fail2ban::filter (
  Array[String] $failregexes,
  Enum['present', 'absent'] $ensure = 'present',
  Array[String] $ignoreregexes = [],
  Array[String] $includes_before = [],
  Array[String] $includes_after = [],
  Array[String] $additional_defs = [],
  String $comment = "",
  ) {

  include ::fail2ban::config

  file { "/etc/fail2ban/filter.d/${name}.conf":
    ensure  => $ensure,
    content => template("${module_name}/filter.erb"),
    owner   => 'root',
    group   => $::fail2ban::config::root_group,
    mode    => '0644',
    require => Class['::fail2ban::config'],
    notify  => Class['::fail2ban::service'],
  }

}
