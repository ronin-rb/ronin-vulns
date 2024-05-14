require 'spec_helper'
require 'ronin/vulns/cli/commands/ssti'
require_relative 'man_page_example'

describe Ronin::Vulns::CLI::Commands::Ssti do
  include_examples "man_page"

  let(:url) { 'https://example.com/page.php?id=1' }

  describe "#option_parser" do
    context "when the '--test-expr' option is parsed" do
      let(:test) { '7*7' }
      let(:argv) { ['--test-expr', test] }

      before { subject.option_parser.parse(argv) }

      it "must set the :test_expr key in #scan_kwargs" do
        kwargs = subject.scan_kwargs

        expect(kwargs[:test_expr]).to be_kind_of(Ronin::Vulns::SSTI::TestExpression)
        expect(kwargs[:test_expr].string).to eq(test)
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
