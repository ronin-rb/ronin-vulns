require 'spec_helper'
require 'ronin/vulns/cli/commands/scan'
require_relative 'man_page_example'

describe Ronin::Vulns::CLI::Commands::Scan do
  include_examples "man_page"

  let(:url) { 'https://example.com/page.php?id=1' }

  describe "#lfi_kwargs" do
    it "must default to an empty Hash" do
      expect(subject.lfi_kwargs).to eq({})
    end

    it "must also set :lfi in scan_kwargs to #lfi_kwargs" do
      subject.lfi_kwargs

      expect(subject.scan_kwargs[:lfi]).to be(subject.lfi_kwargs)
    end
  end

  describe "#rfi_kwargs" do
    it "must default to an empty Hash" do
      expect(subject.rfi_kwargs).to eq({})
    end

    it "must also set :rfi in scan_kwargs to #rfi_kwargs" do
      subject.rfi_kwargs

      expect(subject.scan_kwargs[:rfi]).to be(subject.rfi_kwargs)
    end
  end

  describe "#sqli_kwargs" do
    it "must default to an empty Hash" do
      expect(subject.sqli_kwargs).to eq({})
    end

    it "must also set :sqli in scan_kwargs to #sqli_kwargs" do
      subject.sqli_kwargs

      expect(subject.scan_kwargs[:sqli]).to be(subject.sqli_kwargs)
    end
  end

  describe "#ssti_kwargs" do
    it "must default to an empty Hash" do
      expect(subject.ssti_kwargs).to eq({})
    end

    it "must also set :ssti in scan_kwargs to #ssti_kwargs" do
      subject.ssti_kwargs

      expect(subject.scan_kwargs[:ssti]).to be(subject.ssti_kwargs)
    end
  end

  describe "#open_redirect_kwargs" do
    it "must default to an empty Hash" do
      expect(subject.open_redirect_kwargs).to eq({})
    end

    it "must also set :open_redirect in scan_kwargs to #open_redirect_kwargs" do
      subject.open_redirect_kwargs

      expect(subject.scan_kwargs[:open_redirect]).to be(subject.open_redirect_kwargs)
    end
  end

  describe "#reflected_xss_kwargs" do
    it "must return an empty Hash by default" do
      expect(subject.reflected_xss_kwargs).to eq({})
    end

    it "must also set :reflected_xss in scan_kwargs to #reflected_xss_kwargs" do
      subject.reflected_xss_kwargs

      expect(subject.scan_kwargs[:reflected_xss]).to be(subject.reflected_xss_kwargs)
    end
  end

  describe "#option_parser" do
    context "when the '--lfi-os' option is parsed" do
      let(:os)   { :windows }
      let(:argv) { ['--lfi-os', os.to_s] }

      before { subject.option_parser.parse(argv) }

      it "must set the :os key in #lfi_kwargs" do
        expect(subject.lfi_kwargs[:os]).to eq(os)
      end
    end

    context "when the '--lfi-depth' option is parsed" do
      let(:depth) { 9 }
      let(:argv)  { ['--lfi-depth', depth.to_s] }

      before { subject.option_parser.parse(argv) }

      it "must set the :depth key in the Hash" do
        expect(subject.lfi_kwargs[:depth]).to eq(depth)
      end
    end

    context "when the '--lfi-filter-bypass' option is parsed" do
      let(:argv) { ['--lfi-filter-bypass', option_value] }

      before { subject.option_parser.parse(argv) }

      context "and it's value is 'null-byte'" do
        let(:option_value)  { 'null-byte' }
        let(:filter_bypass) { :null_byte }

        it "must set the :filter_bypass key in #lfi_kwargs to :null_byte" do
          expect(subject.lfi_kwargs[:filter_bypass]).to eq(filter_bypass)
        end
      end

      context "and it's value is 'double-escape'" do
        let(:option_value)  { 'double-escape' }
        let(:filter_bypass) { :double_escape }

        it "must set the :filter_bypass key in #lfi_kwargs to :double_escape" do
          expect(subject.lfi_kwargs[:filter_bypass]).to eq(filter_bypass)
        end
      end

      context "and it's value is 'base64'" do
        let(:option_value)  { 'base64' }
        let(:filter_bypass) { :base64 }

        it "must set the :filter_bypass key in #lfi_kwargs to :base64" do
          expect(subject.lfi_kwargs[:filter_bypass]).to eq(filter_bypass)
        end
      end

      context "and it's value is 'rot13'" do
        let(:option_value)  { 'rot13' }
        let(:filter_bypass) { :rot13 }

        it "must set the :filter_bypass key in #lfi_kwargs to :rot13" do
          expect(subject.lfi_kwargs[:filter_bypass]).to eq(filter_bypass)
        end
      end

      context "and it's value is 'zlib'" do
        let(:option_value)  { 'zlib' }
        let(:filter_bypass) { :zlib }

        it "must set the :filter_bypass key in #lfi_kwargs to :zlib" do
          expect(subject.lfi_kwargs[:filter_bypass]).to eq(filter_bypass)
        end
      end
    end

    context "when the '--rfi-filter-bypass' option is parsed" do
      let(:argv) { ['--rfi-filter-bypass', option_value] }

      before { subject.option_parser.parse(argv) }

      context "when the option value is 'double-encode'" do
        let(:option_value)  { 'double-encode' }
        let(:filter_bypass) { :double_encode }

        it "must set the :filter_bypass key in the #rfi_kwargs to :double_encode" do
          expect(subject.rfi_kwargs[:filter_bypass]).to eq(filter_bypass)
        end
      end

      context "when the option value is 'suffix-escape'" do
        let(:option_value)  { 'suffix-escape' }
        let(:filter_bypass) { :suffix_escape }

        it "must set the :filter_bypass key in the #rfi_kwargs to :suffix_escape" do
          expect(subject.rfi_kwargs[:filter_bypass]).to eq(filter_bypass)
        end
      end

      context "when the option value is 'null-byte'" do
        let(:option_value)  { 'null-byte' }
        let(:filter_bypass) { :null_byte }

        it "must set the :filter_bypass key in the #rfi_kwargs to :null_byte" do
          expect(subject.rfi_kwargs[:filter_bypass]).to eq(filter_bypass)
        end
      end
    end

    context "when the '--rfi-script-lang' option is parsed" do
      let(:argv) { ['--rfi-script-lang', option_value] }

      before { subject.option_parser.parse(argv) }

      context "when the option value is 'asp'" do
        let(:option_value) { 'asp' }
        let(:script_lang)  { :asp }

        it "must set the :script_lang key in #rfi_kwargs to :asp" do
          expect(subject.rfi_kwargs[:script_lang]).to eq(script_lang)
        end
      end

      context "when the option value is 'asp.net'" do
        let(:option_value) { 'asp.net' }
        let(:script_lang)  { :asp_net }

        it "must set the :script_lang key in #rfi_kwargs to :asp_net" do
          expect(subject.rfi_kwargs[:script_lang]).to eq(script_lang)
        end
      end

      context "when the option value is 'coldfusion'" do
        let(:option_value) { 'coldfusion' }
        let(:script_lang)  { :cold_fusion }

        it "must set the :script_lang key in #rfi_kwargs to :cold_fusion" do
          expect(subject.rfi_kwargs[:script_lang]).to eq(script_lang)
        end
      end

      context "when the option value is 'jsp'" do
        let(:option_value) { 'jsp' }
        let(:script_lang)  { :jsp }

        it "must set the :script_lang key in #rfi_kwargs to :jsp" do
          expect(subject.rfi_kwargs[:script_lang]).to eq(script_lang)
        end
      end

      context "when the option value is 'php'" do
        let(:option_value) { 'php' }
        let(:script_lang)  { :php }

        it "must set the :script_lang key in #rfi_kwargs to :php" do
          expect(subject.rfi_kwargs[:script_lang]).to eq(script_lang)
        end
      end

      context "when the option value is 'perl'" do
        let(:option_value) { 'perl' }
        let(:script_lang)  { :perl }

        it "must set the :script_lang key in #rfi_kwargs to :perl" do
          expect(subject.rfi_kwargs[:script_lang]).to eq(script_lang)
        end
      end
    end

    context "when the '--rfi-test-script-url' option is parsed" do
      let(:test_script_url) { 'https://other-website.com/path/to/rfi_test.php' }
      let(:argv) { ['--rfi-test-script-url', test_script_url] }

      before { subject.option_parser.parse(argv) }

      it "must set the :test_script_url key in the Hash" do
        expect(subject.rfi_kwargs[:test_script_url]).to eq(test_script_url)
      end
    end

    context "when the '--sqli-escape-quote' option is parsed" do
      let(:argv) { %w[--sqli-escape-quote] }

      before { subject.option_parser.parse(argv) }

      it "must set the :escape_quote key in the Hash" do
        expect(subject.sqli_kwargs[:escape_quote]).to be(true)
      end
    end

    context "when the '--sqli-escape-parens' option is parsed" do
      let(:argv) { %w[--sqli-escape-parens] }

      before { subject.option_parser.parse(argv) }

      it "must set the :escape_parens key in the Hash" do
        expect(subject.sqli_kwargs[:escape_parens]).to be(true)
      end
    end

    context "when the '--sqli-terminate' option is parsed" do
      let(:argv) { %w[--sqli-terminate] }

      before { subject.option_parser.parse(argv) }

      it "must set the :terminate key in the Hash" do
        expect(subject.sqli_kwargs[:terminate]).to be(true)
      end
    end

    context "when the '--ssti-test-expr' option is parsed" do
      let(:test) { '7*7' }
      let(:argv) { ['--ssti-test-expr', test] }

      before { subject.option_parser.parse(argv) }

      it "must set the :test_expr key in the Hash" do
        kwargs = subject.ssti_kwargs

        expect(kwargs[:test_expr]).to be_kind_of(Ronin::Vulns::SSTI::TestExpression)
        expect(kwargs[:test_expr].string).to eq(test)
      end
    end

    context "when the '--open-redirect-url' option is parsed" do
      let(:test_url) { 'https://example.com/test' }
      let(:argv)     { ['--open-redirect-url', test_url] }

      before { subject.option_parser.parse(argv) }

      it "must set the :test_url key in the Hash" do
        expect(subject.open_redirect_kwargs[:test_url]).to eq(test_url)
      end
    end
  end

  describe "#scan_url" do
    it "must call Ronin::Vulns::URLScanner.scan with the URL and #scan_kwargs" do
      expect(Ronin::Vulns::URLScanner).to receive(:scan).with(
        url, **subject.scan_kwargs
      )

      subject.scan_url(url)
    end
  end

  describe "#test_url" do
    it "must call Ronin::Vulns::URLScanner.scan with the URL and #scan_kwargs" do
      expect(Ronin::Vulns::URLScanner).to receive(:test).with(
        url, **subject.scan_kwargs
      )

      subject.test_url(url)
    end
  end
end
