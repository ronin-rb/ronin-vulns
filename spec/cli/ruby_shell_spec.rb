require 'spec_helper'
require 'ronin/vulns/cli/ruby_shell'

describe Ronin::Vulns::CLI::RubyShell do
  describe "#initialize" do
    it "must default #name to 'ronin-vulns'" do
      expect(subject.name).to eq('ronin-vulns')
    end

    it "must default context: to Ronin::Vulns" do
      expect(subject.context).to be_a(Object)
      expect(subject.context).to be_kind_of(Ronin::Vulns)
    end
  end
end
