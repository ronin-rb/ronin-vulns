require 'spec_helper'
require 'ronin/vulns/cli/commands/irb'
require_relative 'man_page_example'

describe Ronin::Vulns::CLI::Commands::Irb do
  include_examples "man_page"
end
