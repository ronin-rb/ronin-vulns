require 'spec_helper'
require 'ronin/vulns/cli/commands/rfi'
require_relative 'man_page_example'

describe Ronin::Vulns::CLI::Commands::Rfi do
  include_examples "man_page"

  let(:url) { 'https://example.com/page.php?id=1' }

  describe "#option_parser" do
    context "when the '--filter-bypass' option is parsed" do
      let(:argv) { ['--filter-bypass', option_value] }

      before { subject.option_parser.parse(argv) }

      context "when the option value is 'double-encode'" do
        let(:option_value)  { 'double-encode' }
        let(:filter_bypass) { :double_encode }

        it "must set the :filter_bypass key in #scan_kwargs to :double_encode" do
          expect(subject.scan_kwargs[:filter_bypass]).to eq(filter_bypass)
        end
      end

      context "when the option value is 'suffix-escape'" do
        let(:option_value)  { 'suffix-escape' }
        let(:filter_bypass) { :suffix_escape }

        it "must set the :filter_bypass key in #scan_kwargs to :suffix_escape" do
          expect(subject.scan_kwargs[:filter_bypass]).to eq(filter_bypass)
        end
      end

      context "when the option value is 'null-byte'" do
        let(:option_value)  { 'null-byte' }
        let(:filter_bypass) { :null_byte }

        it "must set the :filter_bypass key in #scan_kwargs to :null_byte" do
          expect(subject.scan_kwargs[:filter_bypass]).to eq(filter_bypass)
        end
      end
    end

    context "when the '--script-lang' option is parsed" do
      let(:argv) { ['--script-lang', option_value] }

      before { subject.option_parser.parse(argv) }

      context "when the option value is 'asp'" do
        let(:option_value) { 'asp' }
        let(:script_lang)  { :asp }

        it "must set the :script_lang key in #scan_kwargs to :asp" do
          expect(subject.scan_kwargs[:script_lang]).to eq(script_lang)
        end
      end

      context "when the option value is 'asp.net'" do
        let(:option_value) { 'asp.net' }
        let(:script_lang)  { :asp_net }

        it "must set the :script_lang key in #scan_kwargs to :asp_net" do
          expect(subject.scan_kwargs[:script_lang]).to eq(script_lang)
        end
      end

      context "when the option value is 'coldfusion'" do
        let(:option_value) { 'coldfusion' }
        let(:script_lang)  { :cold_fusion }

        it "must set the :script_lang key in #scan_kwargs to :cold_fusion" do
          expect(subject.scan_kwargs[:script_lang]).to eq(script_lang)
        end
      end

      context "when the option value is 'jsp'" do
        let(:option_value) { 'jsp' }
        let(:script_lang)  { :jsp }

        it "must set the :script_lang key in #scan_kwargs to :jsp" do
          expect(subject.scan_kwargs[:script_lang]).to eq(script_lang)
        end
      end

      context "when the option value is 'php'" do
        let(:option_value) { 'php' }
        let(:script_lang)  { :php }

        it "must set the :script_lang key in #scan_kwargs to :php" do
          expect(subject.scan_kwargs[:script_lang]).to eq(script_lang)
        end
      end

      context "when the option value is 'perl'" do
        let(:option_value) { 'perl' }
        let(:script_lang)  { :perl }

        it "must set the :script_lang key in #scan_kwargs to :perl" do
          expect(subject.scan_kwargs[:script_lang]).to eq(script_lang)
        end
      end
    end

    context "when the '--test-script-url' option is parsed" do
      let(:test_script_url) { 'https://other-website.com/path/to/rfi_test.php' }
      let(:argv) { ['--test-script-url', test_script_url] }

      before { subject.option_parser.parse(argv) }

      it "must set the :test_script_url key in #scan_kwargs" do
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
