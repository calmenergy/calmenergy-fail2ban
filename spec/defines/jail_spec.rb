require 'spec_helper'
describe 'fail2ban::jail' do
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
      context 'with no params' do
        let (:params) {{}}
        let (:title) {'fooey'}
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_fail2ban__jail('fooey') }
        it { is_expected.to contain_class('fail2ban::service') }
        it { is_expected.to contain_class('fail2ban') }
        if (facts[:operatingsystem] == 'Debian' and facts[:operatingsystemmajrelease] < '8')
          it do
            is_expected.to contain_concat__fragment('jail_fooey').
              with_target('/etc/fail2ban/jail.local').
              with_order(10). # 10 is the default provided by concat module.
              with_content(/^\[fooey\]/).
              with_content(/^enabled *= *true/).
              without_content(/port/).
              without_content(/filter/).
              without_content(/logpath/).
              without_content(/protocol/).
              without_content(/maxretry/).
              without_content(/findtime/).
              without_content(/^action/).
              without_content(/^banaction/).
              without_content(/^bantime/).
              without_content(/ignoreip/).
              without_content(/backend/)
          end
        else
          it do
            is_expected.to contain_file('/etc/fail2ban/jail.d/fooey.conf').
              with_ensure('present').
              with_owner('root').
              with_group(expected_root_group).
              with_mode('0644').
              with_content(/^\[fooey\]/).
              with_content(/^enabled *= *true/).
              without_content(/port/).
              without_content(/filter/).
              without_content(/logpath/).
              without_content(/protocol/).
              without_content(/maxretry/).
              without_content(/findtime/).
              without_content(/^action/).
              without_content(/^banaction/).
              without_content(/^bantime/).
              without_content(/ignoreip/).
              without_content(/backend/)
          end
        end
      end
      context 'with all params' do
        let (:params) do
          {
            :port => 4731,
            :filter => 'myfilter',
            :log_path => '/var/log/yeah',
            :ensure   => 'absent',
            :enabled  => false,
            :protocol => 'udp',
            :maxretry => 28,
            :findtime => 304,
            :action    => 'flipout',
            :banaction => 'shout',
            :bantime   => 187,
            :ignoreip  => ['foo.com', '172.24.8.0/24', '132.98.47.1'],
            :order     => 25,
            :backend   => 'polling'
          }
        end
        let (:title) {'wigwam'}
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_fail2ban__jail('wigwam') }
        it { is_expected.to contain_class('fail2ban::service') }
        it { is_expected.to contain_class('fail2ban') }
        if (facts[:operatingsystem] == 'Debian' and facts[:operatingsystemmajrelease] < '8')
          it {is_expected.to contain_notify('no_ensure_wheezy') }
          it do
            is_expected.to contain_concat__fragment('jail_wigwam').
              with_target('/etc/fail2ban/jail.local').
              with_order(25).
              with_content(/^\[wigwam\]/).
              with_content(/^enabled *= *false/).
              with_content(/port *= *4731/).
              with_content(/filter *= *myfilter/).
              with_content(/logpath *= *\/var\/log\/yeah/).
              with_content(/protocol *= *udp/).
              with_content(/maxretry *= *28/).
              with_content(/findtime *= *304/).
              with_content(/^action *= *flipout/).
              with_content(/^banaction *= *shout/).
              with_content(/bantime *= *187/).
              with_content(/ignoreip *= *foo\.com 172\.24\.8\.0\/24 132\.98\.47\.1/).
              with_content(/backend *= *polling/)
          end
        else
          it { is_expected.to contain_notify('order_only_with_wheezy') }
          it do
            is_expected.to contain_file('/etc/fail2ban/jail.d/wigwam.conf').
              with_ensure('absent').
              with_owner('root').
              with_group(expected_root_group).
              with_mode('0644').
              with_content(/^\[wigwam\]/).
              with_content(/^enabled *= *false/).
              with_content(/port *= *4731/).
              with_content(/filter *= *myfilter/).
              with_content(/logpath *= *\/var\/log\/yeah/).
              with_content(/protocol *= *udp/).
              with_content(/maxretry *= *28/).
              with_content(/findtime *= *304/).
              with_content(/^action *= *flipout/).
              with_content(/^banaction *= *shout/).
              with_content(/bantime *= *187/).
              with_content(/ignoreip *= *foo\.com 172\.24\.8\.0\/24 132\.98\.47\.1/).
              with_content(/backend *= *polling/)
          end
        end
      end
    end
  end
end
