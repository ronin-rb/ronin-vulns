require 'spec_helper'
require 'ronin/vulns/cli/commands/lfi'
require_relative 'man_page_example'

describe Ronin::Vulns::CLI::Commands::Lfi do
  include_examples "man_page"

  let(:url) { 'https://example.com/page.php?id=1' }

  describe "#scan_kwargs" do
    context "when #options[:os] is set" do
      let(:os)   { :windows     }
      let(:argv) { ['--os', os.to_s] }

      before { subject.option_parser.parse(argv) }

      it "must set the :os key in the Hash" do
        expect(subject.scan_kwargs[:os]).to eq(os)
      end
    end

    context "when #options[:depth] is set" do
      let(:depth) { 9 }
      let(:argv)  { ['--depth', depth.to_s] }

      before { subject.option_parser.parse(argv) }

      it "must set the :depth key in the Hash" do
        expect(subject.scan_kwargs[:depth]).to eq(depth)
      end
    end

    context "when #options[:filter_bypass] is set" do
      let(:filter_bypass) { :base64 }
      let(:argv) { ['--filter-bypass', filter_bypass.to_s] }

      before { subject.option_parser.parse(argv) }

      it "must set the :filter_bypass key in the Hash" do
        expect(subject.scan_kwargs[:filter_bypass]).to eq(filter_bypass)
      end
    end
  end

  describe "#scan_url" do
    it "must call Ronin::Vulns::LFI.scan with the URL and #scan_kwargs" do
      expect(Ronin::Vulns::LFI).to receive(:scan).with(
        url, **subject.scan_kwargs
      )

      subject.scan_url(url)
    end
  end

  describe "#test_url" do
    it "must call Ronin::Vulns::LFI.scan with the URL and #scan_kwargs" do
      expect(Ronin::Vulns::LFI).to receive(:test).with(
        url, **subject.scan_kwargs
      )

      subject.test_url(url)
    end
  end
end
