require 'spec_helper'
describe 'fail2ban::config' do
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
        it { is_expected.to contain_class('fail2ban::config') }
        if (facts[:operatingsystem] == 'Debian' and facts[:operatingsystemmajrelease] < '8')
          it { is_expected.not_to contain_file('/etc/fail2ban/jail.d') }
          it { is_expected.not_to contain_file('/etc/fail2ban/jail.local') }
          it { is_expected.to contain_notify('wheezy_no_purge_jail') }
          it do
            is_expected.to contain_concat('/etc/fail2ban/jail.local').
              with_owner('root').
              with_group(expected_root_group).
              with_mode('0644')
          end
          it do
            is_expected.to contain_concat__fragment('jail_header').
              with_target('/etc/fail2ban/jail.local').
              with_order(1).
              with_content(/^\[DEFAULT\]/).
              without_content(/ignoreip/).
              without_content(/bantime/).
              without_content(/findtime/).
              without_content(/maxretry/).
              without_content(/backend/).
              without_content(/usedns/).
              without_content(/destemail/).
              without_content(/sender/).
              without_content(/mta/).
              without_content(/protocol/).
              with_content(/chain *= *FAIL2BAN/).
              without_content(/banaction/).
              without_content(/^action/)
          end
        else
          it { is_expected.not_to contain_concat('/etc/fail2ban/jail.local') }
          it { is_expected.not_to contain_concat_fragment('jail_header') }
          it do
            is_expected.to contain_file('/etc/fail2ban/jail.d').
              with_ensure('directory').
              with_recurse(true).
              with_purge(true).
              with_owner('root').
              with_group(expected_root_group).
              with_mode('0700')
          end
          it do
            is_expected.to contain_file('/etc/fail2ban/jail.local').
              with_ensure('file').
              with_owner('root').
              with_group(expected_root_group).
              with_mode('0400').
              with_content(/^\[DEFAULT\]/).
              without_content(/ignoreip/).
              without_content(/bantime/).
              without_content(/findtime/).
              without_content(/maxretry/).
              without_content(/backend/).
              without_content(/usedns/).
              without_content(/destemail/).
              without_content(/sender/).
              without_content(/mta/).
              without_content(/protocol/).
              with_content(/chain *= *FAIL2BAN/).
              without_content(/banaction/).
              without_content(/^action/)
          end
        end
        it do
          is_expected.to contain_file('/etc/fail2ban/fail2ban.local').
            with_ensure('file').
            with_owner('root').
            with_group(expected_root_group).
            with_mode('0400').
            with_content(/^\[Definition\]/).
            without_content(/logleven/).
            without_content(/logtarget/).
            without_content(/syslogsocket/).
            without_content(/socket/).
            without_content(/pidfile/).
            without_content(/dbfile/).
            without_content(/dbpurgeage/)
        end
        it { is_expected.to contain_firewallchain('FAIL2BAN:filter:IPv4').with_purge(false) }
        it do
          is_expected.to contain_firewall('000 Check fail2ban').
            with_chain('INPUT').
            with_jump('FAIL2BAN')
        end
        it do
          is_expected.to contain_firewall('999 Return to INPUT').
            with_chain('FAIL2BAN').
            with_jump('RETURN')
        end
      end
      context 'with all params from hiera' do
        let (:node) {'fail2ban.all'}
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('fail2ban::config') }
        if (facts[:operatingsystem] == 'Debian' and facts[:operatingsystemmajrelease] < '8')
          it { is_expected.not_to contain_file('/etc/fail2ban/jail.d') }
          it { is_expected.not_to contain_file('/etc/fail2ban/jail.local') }
          it do
            is_expected.to contain_concat('/etc/fail2ban/jail.local').
              with_owner('root').
              with_group('toot').
              with_mode('0644')
          end
          it do
            is_expected.to contain_concat__fragment('jail_header').
              with_target('/etc/fail2ban/jail.local').
              with_order(1).
              with_content(/^\[DEFAULT\]/).
              with_content(/ignoreip *= *123\.45\.67\.89 *132\.54\.76\.98/).
              with_content(/bantime *= *601/).
              with_content(/findtime *= *602/).
              with_content(/maxretry *= *4/).
              with_content(/backend *= *gamin/).
              with_content(/usedns *= *no/).
              with_content(/destemail *= *here@there/).
              with_content(/sender *= *nobody@nowhere/).
              with_content(/mta *= *tossmail/).
              with_content(/protocol *= *udp/).
              with_content(/chain *= *ODDCHAIN/).
              with_content(/banaction *= *dummy\-banaction/).
              with_content(/^action *= *f2bact/)
          end
        else
          it { is_expected.not_to contain_concat('/etc/fail2ban/jail.local') }
          it { is_expected.not_to contain_concat_fragment('jail_header') }
          it do
            is_expected.to contain_file('/etc/fail2ban/jail.d').
              with_ensure('directory').
              with_recurse(true).
              with_purge(false).
              with_owner('root').
              with_group('toot').
              with_mode('0700')
          end
          it do
            is_expected.to contain_file('/etc/fail2ban/jail.local').
              with_ensure('file').
              with_owner('root').
              with_group('toot').
              with_mode('0400').
              with_content(/^\[DEFAULT\]/).
              with_content(/ignoreip *= *123\.45\.67\.89 *132\.54\.76\.98/).
              with_content(/bantime *= *601/).
              with_content(/findtime *= *602/).
              with_content(/maxretry *= *4/).
              with_content(/backend *= *gamin/).
              with_content(/usedns *= *no/).
              with_content(/destemail *= *here@there/).
              with_content(/sender *= *nobody@nowhere/).
              with_content(/mta *= *tossmail/).
              with_content(/protocol *= *udp/).
              with_content(/chain *= *ODDCHAIN/).
              with_content(/banaction *= *dummy\-banaction/).
              with_content(/^action *= *f2bact/)
          end
        end
        it do
          is_expected.to contain_file('/etc/fail2ban/fail2ban.local').
            with_ensure('file').
            with_owner('root').
            with_group('toot').
            with_mode('0400').
            with_content(/^\[Definition\]/).
            with_content(/loglevel *= *CRITICAL/).
            with_content(/logtarget *= *\/var\/log\/monkey/).
            with_content(/syslogsocket *= *\/var\/sock\/woah/).
            with_content(/socket *= *\/var\/sock\/hooey/).
            with_content(/pidfile *= *\/var\/run\/away/).
            with_content(/dbfile *= *:memory:/).
            with_content(/dbpurgeage *= *487321/)
        end
        it { is_expected.to contain_firewallchain('ODDCHAIN:filter:IPv4').with_purge(false) }
        it do
          is_expected.to contain_firewall('000 Check fail2ban').
            with_chain('INPUT').
            with_jump('ODDCHAIN')
        end
        it do
          is_expected.to contain_firewall('999 Return to INPUT').
            with_chain('ODDCHAIN').
            with_jump('RETURN')
        end
      end
    end
  end
end
