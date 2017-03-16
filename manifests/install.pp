# class fail2ban::install
# This class should not be included directly; use the main fail2ban class.
# class.
class fail2ban::install {

  include ::fail2ban

  package { $::fail2ban::package_name:
    ensure => $::fail2ban::package_ensure,
    }
}
