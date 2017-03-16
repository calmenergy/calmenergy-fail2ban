require 'puppetlabs_spec_helper/module_spec_helper'
require 'rspec-puppet-facts'
require 'rspec-puppet'

include RspecPuppetFacts


RSpec.configure do |c|
  c.strict_variables = true
  c.hiera_config     = File.expand_path(File.join(__FILE__, '../fixtures/hiera.yaml'))
end


# Deal with missing fact in puppet firewall module
add_custom_fact :concat_basedir, '/tmp/concat/basedir'
