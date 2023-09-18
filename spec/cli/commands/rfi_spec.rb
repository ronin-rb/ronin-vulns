require 'spec_helper'
require 'ronin/vulns/cli/commands/rfi'
require_relative 'man_page_example'

describe Ronin::Vulns::CLI::Commands::Rfi do
  include_examples "man_page"

  let(:url) { 'https://example.com/page.php?id=1' }

  describe "#option_parser" do
    context "when the '--filter-bypass' option is parsed" do
      let(:filter_bypass) { :suffix_escape }
      let(:argv) { ['--filter-bypass', 'suffix-escape'] }

      before { subject.option_parser.parse(argv) }

      it "must set the :filter_bypass key in the Hash" do
        expect(subject.scan_kwargs[:filter_bypass]).to eq(filter_bypass)
      end
    end

    context "when the '--script-lang' option is parsed" do
      let(:script_lang) { :asp_net }
      let(:argv) { ['--script-lang', 'asp.net'] }

      before { subject.option_parser.parse(argv) }

      it "must set the :script_lang key in the Hash" do
        expect(subject.scan_kwargs[:script_lang]).to eq(script_lang)
      end
    end

    context "when the '--test-script-url' option is parsed" do
      let(:test_script_url) { 'https://other-website.com/path/to/rfi_test.php' }
      let(:argv) { ['--test-script-url', test_script_url] }

      before { subject.option_parser.parse(argv) }

      it "must set the :test_script_url key in the Hash" do
        expect(subject.scan_kwargs[:test_script_url]).to eq(test_script_url)
      end
    end
  end

  describe "#scan_url" do
    it "must call Ronin::Vulns::RFI.scan with the URL and #scan_kwargs" do
      expect(Ronin::Vulns::RFI).to receive(:scan).with(
        url, **subject.scan_kwargs
      )

      subject.scan_url(url)
    end
  end

  describe "#test_url" do
    it "must call Ronin::Vulns::RFI.scan with the URL and #scan_kwargs" do
      expect(Ronin::Vulns::RFI).to receive(:test).with(
        url, **subject.scan_kwargs
      )

      subject.test_url(url)
    end
  end
end
