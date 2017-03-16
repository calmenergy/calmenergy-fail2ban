require 'spec_helper'
describe 'fail2ban::service' do
  on_supported_os.each do |os, facts|
    context "on #{os}" do
      let (:facts) {facts}
      it { is_expected.to compile.with_all_deps }
      it { is_expected.to contain_class('fail2ban::service') }
      it { is_expected.to contain_class('fail2ban') }
      it do
        is_expected.to contain_service('fail2ban').
          with_ensure('running').
          with_enable(true).
          with_hasstatus(true)
      end
    end
  end
end
