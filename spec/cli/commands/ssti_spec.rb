require 'spec_helper'
require 'ronin/vulns/cli/commands/ssti'

describe Ronin::Vulns::CLI::Commands::Ssti do
  let(:url) { 'https://example.com/page.php?id=1' }

  describe "#scan_kwargs" do
    context "when #test_url is set" do
      let(:test) { '7*7' }
      let(:argv) { ['--test', test] }

      before { subject.option_parser.parse(argv) }

      it "must set the :test key in the Hash" do
        kwargs = subject.scan_kwargs

        expect(kwargs[:test]).to be_kind_of(Ronin::Vulns::SSTI::TestExpression)
        expect(kwargs[:test].string).to eq(test)
      end
    end
  end

  describe "#scan_url" do
    it "must call Ronin::Vulns::SSTI.scan with the URL and #scan_kwargs" do
      expect(Ronin::Vulns::SSTI).to receive(:scan).with(
        url, **subject.scan_kwargs
      )

      subject.scan_url(url)
    end
  end

  describe "#test_url" do
    it "must call Ronin::Vulns::SSTI.scan with the URL and #scan_kwargs" do
      expect(Ronin::Vulns::SSTI).to receive(:test).with(
        url, **subject.scan_kwargs
      )

      subject.test_url(url)
    end
  end
end
