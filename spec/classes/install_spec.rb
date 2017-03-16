require 'spec_helper'
describe 'fail2ban::install' do
  on_supported_os.each do |os, facts|
    context "on #{os}" do
      let (:facts) {facts}
      context 'with defaults for all parameters' do
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('fail2ban::install') }
        it { is_expected.to contain_class('fail2ban') }
        it { is_expected.to contain_package('fail2ban').with_ensure('latest') }
      end
      context 'with package and ensure from hiera' do
        let (:node) {'fail2ban.all'}
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('fail2ban::install') }
        it { is_expected.to contain_class('fail2ban') }
        it { is_expected.to contain_package('phail2banne').with_ensure('172.24.b3') }
      end
    end
  end
end
