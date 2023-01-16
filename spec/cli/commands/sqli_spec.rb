require 'spec_helper'
require 'ronin/vulns/cli/commands/sqli'
require_relative 'man_page_example'

describe Ronin::Vulns::CLI::Commands::Sqli do
  include_examples "man_page"

  let(:url) { 'https://example.com/page.php?id=1' }

  describe "#scan_kwargs" do
    context "when #options[:escape_quote] is set" do
      let(:argv) { %w[--escape-quote] }

      before { subject.option_parser.parse(argv) }

      it "must set the :escape_quote key in the Hash" do
        expect(subject.scan_kwargs[:escape_quote]).to be(true)
      end
    end

    context "when #options[:escape_parens] is set" do
      let(:argv) { %w[--escape-parens] }

      before { subject.option_parser.parse(argv) }

      it "must set the :escape_parens key in the Hash" do
        expect(subject.scan_kwargs[:escape_parens]).to be(true)
      end
    end

    context "when #options[:terminate] is set" do
      let(:argv) { %w[--terminate] }

      before { subject.option_parser.parse(argv) }

      it "must set the :terminate key in the Hash" do
        expect(subject.scan_kwargs[:terminate]).to be(true)
      end
    end
  end

  describe "#scan_url" do
    it "must call Ronin::Vulns::SQLI.scan with the URL and #scan_kwargs" do
      expect(Ronin::Vulns::SQLI).to receive(:scan).with(
        url, **subject.scan_kwargs
      )

      subject.scan_url(url)
    end
  end

  describe "#test_url" do
    it "must call Ronin::Vulns::SQLI.scan with the URL and #scan_kwargs" do
      expect(Ronin::Vulns::SQLI).to receive(:test).with(
        url, **subject.scan_kwargs
      )

      subject.test_url(url)
    end
  end
end
