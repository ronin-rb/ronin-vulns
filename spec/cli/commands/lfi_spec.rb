require 'spec_helper'
require 'ronin/vulns/cli/commands/lfi'
require_relative 'man_page_example'

describe Ronin::Vulns::CLI::Commands::Lfi do
  include_examples "man_page"

  let(:url) { 'https://example.com/page.php?id=1' }

  describe "#option_parser" do
    context "when the '--os' option is parsed" do
      let(:os)   { :windows }
      let(:argv) { ['--os', os.to_s] }

      before { subject.option_parser.parse(argv) }

      it "must set the :os key in the Hash" do
        expect(subject.scan_kwargs[:os]).to eq(os)
      end
    end

    context "when the '--depth' option is parsed" do
      let(:depth) { 9 }
      let(:argv)  { ['--depth', depth.to_s] }

      before { subject.option_parser.parse(argv) }

      it "must set the :depth key in the Hash" do
        expect(subject.scan_kwargs[:depth]).to eq(depth)
      end
    end

    context "when the '--filter-bypass' option is parsed" do
      let(:argv) { ['--filter-bypass', option_value] }

      before { subject.option_parser.parse(argv) }

      context "and it's value is 'null-byte'" do
        let(:option_value)  { 'null-byte' }
        let(:filter_bypass) { :null_byte }

        it "must set the :filter_bypass key in the Hash to :null_byte" do
          expect(subject.scan_kwargs[:filter_bypass]).to eq(filter_bypass)
        end
      end

      context "and it's value is 'double-escape'" do
        let(:option_value)  { 'double-escape' }
        let(:filter_bypass) { :double_escape }

        it "must set the :filter_bypass key in the Hash to :double_escape" do
          expect(subject.scan_kwargs[:filter_bypass]).to eq(filter_bypass)
        end
      end

      context "and it's value is 'base64'" do
        let(:option_value)  { 'base64' }
        let(:filter_bypass) { :base64 }

        it "must set the :filter_bypass key in the Hash to :base64" do
          expect(subject.scan_kwargs[:filter_bypass]).to eq(filter_bypass)
        end
      end

      context "and it's value is 'rot13'" do
        let(:option_value)  { 'rot13' }
        let(:filter_bypass) { :rot13 }

        it "must set the :filter_bypass key in the Hash to :rot13" do
          expect(subject.scan_kwargs[:filter_bypass]).to eq(filter_bypass)
        end
      end

      context "and it's value is 'zlib'" do
        let(:option_value)  { 'zlib' }
        let(:filter_bypass) { :zlib }

        it "must set the :filter_bypass key in the Hash to :zlib" do
          expect(subject.scan_kwargs[:filter_bypass]).to eq(filter_bypass)
        end
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
