# class fail2ban::service
# This class should not be included directly; use the main fail2ban class.
class fail2ban::service {

  include ::fail2ban

  service { 'fail2ban':
    ensure    => running,
    enable    => true,
    hasstatus => true,
  }

}
