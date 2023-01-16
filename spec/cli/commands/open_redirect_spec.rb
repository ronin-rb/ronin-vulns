require 'spec_helper'
require 'ronin/vulns/cli/commands/open_redirect'
require_relative 'man_page_example'

describe Ronin::Vulns::CLI::Commands::OpenRedirect do
  include_examples "man_page"

  let(:url) { 'https://example.com/page.php?id=1' }

  describe "#scan_kwargs" do
    context "when #options[:test_url] is set" do
      let(:test_url) { 'https://example.com/test' }
      let(:argv)     { ['--test-url', test_url]   }

      before { subject.option_parser.parse(argv) }

      it "must set the :test_url key in the Hash" do
        expect(subject.scan_kwargs[:test_url]).to eq(test_url)
      end
    end
  end

  describe "#scan_url" do
    it "must call Ronin::Vulns::OpenRedirect.scan with the URL and #scan_kwargs" do
      expect(Ronin::Vulns::OpenRedirect).to receive(:scan).with(
        url, **subject.scan_kwargs
      )

      subject.scan_url(url)
    end
  end

  describe "#test_url" do
    it "must call Ronin::Vulns::OpenRedirect.scan with the URL and #scan_kwargs" do
      expect(Ronin::Vulns::OpenRedirect).to receive(:test).with(
        url, **subject.scan_kwargs
      )

      subject.test_url(url)
    end
  end
end
