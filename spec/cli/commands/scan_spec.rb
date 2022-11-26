require 'spec_helper'
require 'ronin/vulns/cli/commands/scan'

describe Ronin::Vulns::CLI::Commands::Scan do
  let(:url) { 'https://example.com/page.php?id=1' }

  describe "#lfi_kwargs" do
    context "when #options[:lfi_os] is set" do
      let(:os)   { :windows }
      let(:argv) { ['--lfi-os', os.to_s] }

      before { subject.option_parser.parse(argv) }

      it "must set the :os key in the Hash" do
        expect(subject.lfi_kwargs[:os]).to eq(os)
      end
    end

    context "when #options[:lfi_depth] is set" do
      let(:depth) { 9 }
      let(:argv)  { ['--lfi-depth', depth.to_s] }

      before { subject.option_parser.parse(argv) }

      it "must set the :depth key in the Hash" do
        expect(subject.lfi_kwargs[:depth]).to eq(depth)
      end
    end

    context "when #options[:lfi_filter_bypass] is set" do
      let(:filter_bypass) { :base64 }
      let(:argv) { ['--lfi-filter-bypass', filter_bypass.to_s] }

      before { subject.option_parser.parse(argv) }

      it "must set the :filter_bypass key in the Hash" do
        expect(subject.lfi_kwargs[:filter_bypass]).to eq(filter_bypass)
      end
    end
  end

  describe "#rfi_kwargs" do
    context "when #options[:rfi_filter_bypass] is set" do
      let(:filter_bypass) { :suffix_escape }
      let(:argv) { ['--rfi-filter-bypass', 'suffix-escape'] }

      before { subject.option_parser.parse(argv) }

      it "must set the :filter_bypass key in the Hash" do
        expect(subject.rfi_kwargs[:filter_bypass]).to eq(filter_bypass)
      end
    end

    context "when #options[:rfi_script_lang] is set" do
      let(:script_lang) { :asp_net }
      let(:argv) { ['--rfi-script-lang', 'asp.net'] }

      before { subject.option_parser.parse(argv) }

      it "must set the :script_lang key in the Hash" do
        expect(subject.rfi_kwargs[:script_lang]).to eq(script_lang)
      end
    end

    context "when #options[:rfi_test_script_url] is set" do
      let(:test_script_url) { 'https://other-website.com/path/to/rfi_test.php' }
      let(:argv) { ['--rfi-test-script-url', test_script_url] }

      before { subject.option_parser.parse(argv) }

      it "must set the :test_script_url key in the Hash" do
        expect(subject.rfi_kwargs[:test_script_url]).to eq(test_script_url)
      end
    end
  end

  describe "#sqli_kwargs" do
    context "when #options[:sqli_escape_quote] is set" do
      let(:argv) { %w[--sqli-escape-quote] }

      before { subject.option_parser.parse(argv) }

      it "must set the :escape_quote key in the Hash" do
        expect(subject.sqli_kwargs[:escape_quote]).to be(true)
      end
    end

    context "when #options[:sqli_escape_parens] is set" do
      let(:argv) { %w[--sqli-escape-parens] }

      before { subject.option_parser.parse(argv) }

      it "must set the :escape_parens key in the Hash" do
        expect(subject.sqli_kwargs[:escape_parens]).to be(true)
      end
    end

    context "when #options[:sqli_terminate] is set" do
      let(:argv) { %w[--sqli-terminate] }

      before { subject.option_parser.parse(argv) }

      it "must set the :terminate key in the Hash" do
        expect(subject.sqli_kwargs[:terminate]).to be(true)
      end
    end
  end

  describe "#ssti_kwargs" do
    context "when #ssti_test_expr is set" do
      let(:test) { '7*7' }
      let(:argv) { ['--ssti-test-expr', test] }

      before { subject.option_parser.parse(argv) }

      it "must set the :test_expr key in the Hash" do
        kwargs = subject.ssti_kwargs

        expect(kwargs[:test_expr]).to be_kind_of(Ronin::Vulns::SSTI::TestExpression)
        expect(kwargs[:test_expr].string).to eq(test)
      end
    end
  end

  describe "#open_redirect_kwargs" do
    context "when #options[:open_redirect_url] is set" do
      let(:test_url) { 'https://example.com/test' }
      let(:argv)     { ['--open-redirect-url', test_url] }

      before { subject.option_parser.parse(argv) }

      it "must set the :test_url key in the Hash" do
        expect(subject.open_redirect_kwargs[:test_url]).to eq(test_url)
      end
    end
  end

  describe "#reflected_xss_kwargs" do
    it "must return an empty Hash by default" do
      expect(subject.reflected_xss_kwargs).to eq({})
    end
  end

  describe "#scan_kwargs" do
    it "must contain the :lfi key with #lfi_kewargs" do
      expect(subject.scan_kwargs[:lfi]).to eq(subject.lfi_kwargs)
    end

    it "must contain the :rfi key with #lfi_kewargs" do
      expect(subject.scan_kwargs[:rfi]).to eq(subject.rfi_kwargs)
    end

    it "must contain the :sqli key with #sqli_kewargs" do
      expect(subject.scan_kwargs[:sqli]).to eq(subject.sqli_kwargs)
    end

    it "must contain the :ssti key with #ssti_kewargs" do
      expect(subject.scan_kwargs[:ssti]).to eq(subject.ssti_kwargs)
    end

    it "must contain the :open_redirect key with #open_redirect_kewargs" do
      expect(subject.scan_kwargs[:open_redirect]).to eq(subject.open_redirect_kwargs)
    end

    it "must contain the :reflected_xss key with #reflected_xss_kewargs" do
      expect(subject.scan_kwargs[:reflected_xss]).to eq(subject.reflected_xss_kwargs)
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
