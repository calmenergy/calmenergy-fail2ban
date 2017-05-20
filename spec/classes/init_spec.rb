require 'spec_helper'
describe 'fail2ban' do
  on_supported_os.each do |os, facts|
    context "on #{os}" do
      let (:facts) {facts}
      let (:expected_root_group) do
        case facts[:operatingsystem] 
        when 'FreeBSD', 'OpenBSD'
          'wheel'
        else
          'root'
        end
      end
      context 'with defaults for all parameters' do
        it { is_expected.to compile.with_all_deps }
        it do
          is_expected.to contain_class('fail2ban').
            with_package_name('fail2ban').
            with_package_ensure('latest').
            without_ignoreip.
            without_log_level.
            without_logtarget.
            without_syslogsocket.
            without_socket.
            without_pidfile.
            without_dbfile.
            without_dbpurgeage.
            without_bantime.
            without_findtime.
            without_maxretry.
            without_backend.
            without_destemail.
            without_email_sender.
            without_mta.
            with_chain('FAIL2BAN').
            without_protocol.
            without_banaction.
            without_action.
            without_usedns.
            with_purge_jail_directory(true).
            with_root_group(expected_root_group)
        end
        it { is_expected.to contain_class('epel') }
        it { is_expected.to contain_class('fail2ban::install').that_comes_before('Class[fail2ban::config]') }
        it { is_expected.to contain_class('fail2ban::config') }
        it do
          is_expected.to contain_class('fail2ban::service').
            that_subscribes_to('Class[fail2ban::config]')
        end
      end
      context 'with all parameters from hiera' do
        let (:node) {'fail2ban.all'}
        it { is_expected.to compile.with_all_deps }
        it do
          is_expected.to contain_class('fail2ban').
            with_package_name('phail2banne').
            with_package_ensure('172.24.b3').
            with_ignoreip(['123.45.67.89', '132.54.76.98']).
            with_log_level('CRITICAL').
            with_logtarget('/var/log/monkey').
            with_syslogsocket('/var/sock/woah').
            with_socket('/var/sock/hooey').
            with_pidfile('/var/run/away').
            with_dbfile(':memory:').
            with_dbpurgeage(487321).
            with_bantime(601).
            with_findtime(602).
            with_maxretry(4).
            with_backend('gamin').
            with_destemail('here@there').
            with_email_sender('nobody@nowhere').
            with_banaction('dummy-banaction').
            with_mta('tossmail').
            with_protocol('udp').
            with_action('f2bact').
            with_usedns('no').
            with_purge_jail_directory(false).
            with_root_group('toot')
        end
        it { is_expected.to contain_class('fail2ban::install').that_comes_before('Class[fail2ban::config]') }
        it { is_expected.to contain_class('fail2ban::config') }
        it do
          is_expected.to contain_class('fail2ban::service').
            that_subscribes_to('Class[fail2ban::config]')
        end
      end
    end
  end
end
