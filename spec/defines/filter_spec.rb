require 'spec_helper'
describe 'fail2ban::filter' do
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
      context 'with only required param failregexes' do
        let (:params) {{:failregexes => ['aaa', 'bbb', 'ccc']}}
        let (:title) {'fooey'}
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('fail2ban::service') }
        it { is_expected.to contain_class('fail2ban') }
        it { is_expected.to contain_fail2ban__filter('fooey') }
        it do
          is_expected.to contain_file('/etc/fail2ban/filter.d/fooey.conf').
            with_ensure('present').
            with_owner('root').
            with_group(expected_root_group).
            with_mode('0644').
            that_requires('Class[fail2ban::config]').
            that_notifies('Class[fail2ban::service]').
            with_content(/^\# Fail2ban filter file fooey\.conf/).
            without_content(/\[INCLUDES\]/).
            without_content(/before *=/).
            without_content(/after *=/).
            with_content(/\[Definition\]/).
            with_content(/failregex *= *aaa\s+bbb\s+ccc/).
            with_content(/ignoreregex *= *$/)
        end
      end
      context 'with all params' do
        let (:params) do
          {
            :failregexes => ['xxx'],
            :ensure => 'absent',
            :ignoreregexes => ['iii', 'jjj'],
            :includes_before => ['ib1', 'ib2'],
            :includes_after  => ['ia1', 'ia2'],
            :additional_defs  => ['abc', 'def = ghi'],
          }
        end
        let (:title) {'wigwam'}
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('fail2ban::service') }
        it { is_expected.to contain_class('fail2ban') }
        it { is_expected.to contain_fail2ban__filter('wigwam') }
        it do
          is_expected.to contain_file('/etc/fail2ban/filter.d/wigwam.conf').
            with_ensure('absent').
            with_owner('root').
            with_group(expected_root_group).
            with_mode('0644').
            that_requires('Class[fail2ban::config]').
            that_notifies('Class[fail2ban::service]').
            with_content(/^\# Fail2ban filter file wigwam\.conf/).
            with_content(/\[INCLUDES\]/).
            with_content(/before *= *ib1\s+ib2/).
            with_content(/after *= *ia1\s+ia2/).
            with_content(/\[Definition\]/).
            with_content(/^abc$/).
            with_content(/^def = ghi/).
            with_content(/failregex *= *xxx$/).
            with_content(/ignoreregex *= *iii\s*jjj$/)
        end
      end
    end
  end
end
