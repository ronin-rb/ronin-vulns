require 'spec_helper'
require 'ronin/vulns/cli/commands/command_injection'
require_relative 'man_page_example'

describe Ronin::Vulns::CLI::Commands::CommandInjection do
  include_examples "man_page"

  let(:url) { 'https://example.com/page.php?id=1' }

  describe "#scan_kwargs" do
    context "when #options[:escape_quote] is set" do
      let(:argv) { %w[--escape-quote '] }

      before { subject.option_parser.parse(argv) }

      it "must set the :escape_quote key in #scan_kwargs" do
        expect(subject.scan_kwargs[:escape_quote]).to eq("'")
      end
    end

    context "when #options[:escape_operator] is set" do
      let(:argv) { %w[--escape-operator ;] }

      before { subject.option_parser.parse(argv) }

      it "must set the :escape_operator key in #scan_kwargs" do
        expect(subject.scan_kwargs[:escape_operator]).to eq(';')
      end
    end

    context "when #options[:terminator] is set" do
      let(:argv) { %w[--terminator ;] }

      before { subject.option_parser.parse(argv) }

      it "must set the :terminator key in #scan_kwargs" do
        expect(subject.scan_kwargs[:terminator]).to eq(';')
      end
    end
  end

  describe "#scan_url" do
    it "must call Ronin::Vulns::CommandInjection .scan with the URL and #scan_kwargs" do
      expect(Ronin::Vulns::CommandInjection).to receive(:scan).with(
        url, **subject.scan_kwargs
      )

      subject.scan_url(url)
    end
  end

  describe "#test_url" do
    it "must call Ronin::Vulns::CommandInjection.scan with the URL and #scan_kwargs" do
      expect(Ronin::Vulns::CommandInjection).to receive(:test).with(
        url, **subject.scan_kwargs
      )

      subject.test_url(url)
    end
  end
end
