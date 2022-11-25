require 'spec_helper'
require 'ronin/vulns/cli/command'

describe Ronin::Vulns::CLI::Command do
  describe ".man_dir" do
    subject { described_class }

    it "must point to the 'man/' directory" do
      expect(subject.man_dir).to eq(File.expand_path(File.join(__dir__,'..','..','man')))
    end

    it "must exist" do
      expect(File.directory?(subject.man_dir)).to be(true)
    end
  end

  describe ".bug_report_url" do
    subject { described_class }

    it "must be 'https://github.com/ronin-rb/ronin-vulns/issues/new'" do
      expect(subject.bug_report_url).to eq('https://github.com/ronin-rb/ronin-vulns/issues/new')
    end
  end
end
