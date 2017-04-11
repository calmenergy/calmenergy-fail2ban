# Class fail2ban.
# Install and configure the fail2ban service.
# The parameters to this class provide defaults for the entire system (via /etc/fail2ban/fail2ban.local) or defaults for all jails
# (via /etc/fail2ban/jail.local).
#
# @example Declaring the class
#    include fail2ban
#
# @param package_name The package name to install.
# @param package_ensure The version number, 'present', installed', 'absent', or 'latest'
# @param log_level The log level for fail2ban's own logging.
# @param logtarget The target to which fail2ban's own logging is sent
# @param syslogsocket The socket belonging to syslogd.
# @param socket Fail2ban's own socket.
# @param pidfile Fail2ban's pidfile.
# @param dbfile The file in which fail2ban stores its persistent database.
# @param dbpurgeage The time, in seconds, after which db entries will be purged.
# @param bantime The time, in seconds, for which offending hosts will be banned.
# @param findtime The time, in seconds, to look back in the logfile to catch repeated attempts.
# @param maxretry The maximum number of retries permitted from the same host before triggering an action
# @param backend the backend to use.
# @param destemail The email address to which to send reports.
# @param email_sender The sender to use as the return address of sent e-mail
# @param mta The mail transport agent to use.
# @param chain The chain into which fail2ban places the jumps to the individual chains belonging to each fail2ban jail.
# @param protocol The protocol to monitor.
# @param banaction The specific ban action to take.
# @param ignoreip Hosts to ignore when applying a jail.
# @param action A reference to one of the action templates defined in jail.conf or jail.local.
# @param usedns Whether to use reverse DNS in checking and reporting breakin attempts.
# @param purge_jail_directory Whether to remove unmanaged entries from Fail2ban's jail directory.
# @param root_group The group owner of system files. 
#
class fail2ban (
  String $package_name                   = 'fail2ban',
  String $package_ensure                 = 'latest',
  Optional[Array[Variant[IP::Address::NoSubnet, IP::Address::V4::CIDR, String]]] $ignoreip = undef,

  Optional[Enum['CRITICAL', 'ERROR',
                'WARNING', 'NOTICE',
                'INFO', 'DEBUG']] $log_level = undef,
  Optional[Variant[Stdlib::Absolutepath, Enum['STDOUT', 'STDERR',
                'SYSLOG']]] $logtarget = undef,
  Optional[String] $syslogsocket = undef,
  Optional[String] $socket = undef,
  Optional[Stdlib::Absolutepath] $pidfile = undef,
  Optional[Variant[Enum[':memory:', 'None'],Stdlib::Absolutepath]] $dbfile = undef,
  Optional[Integer] $dbpurgeage = undef,
  Optional[Integer] $bantime    = undef,
  Optional[Integer] $findtime   = undef,
  Optional[Integer] $maxretry   = undef,
  Optional[Enum['pyinotify', 'gamin', 'polling', 'systemd', 'auto']] $backend      = undef,
  Optional[String] $destemail            = undef,
  Optional[String] $email_sender         = undef,
  Optional[String] $mta                  = undef,
  String           $chain                = 'FAIL2BAN',
  Optional[Enum['udp', 'tcp', 'icmp', 'all']] $protocol          = undef,
  Optional[String] $banaction             = undef,
  Optional[String] $action                = undef,
  Optional[Enum['yes', 'no', 'warn']] $usedns = undef,
  Boolean $purge_jail_directory          = true,
  String $root_group                     =  $::operatingsystem ? {
    /(?i:FreeBSD|OpenBSD)/ => 'wheel',
    default                => 'root',
  }
  ) {

  contain ::fail2ban::install
  contain ::fail2ban::config
  contain ::fail2ban::service

  Class['::fail2ban::install']
  -> Class['::fail2ban::config']
  ~> Class['::fail2ban::service']

}
