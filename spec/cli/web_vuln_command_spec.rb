require 'spec_helper'
require 'ronin/vulns/cli/web_vuln_command'

require 'tempfile'

describe Ronin::Vulns::CLI::WebVulnCommand do
  describe "#initialize" do
    it "must default #scan_mode to :first" do
      expect(subject.scan_mode).to eq(:first)
    end

    it "must default #headers to nil" do
      expect(subject.headers).to be(nil)
    end

    it "must default #raw_cookie to nil" do
      expect(subject.raw_cookie).to be(nil)
    end

    it "must default #cookie to nil" do
      expect(subject.cookie).to be(nil)
    end

    it "must default #referer to nil" do
      expect(subject.referer).to be(nil)
    end

    it "must default #form_data to nil" do
      expect(subject.form_data).to be(nil)
    end

    it "must default #test_query_params to nil" do
      expect(subject.test_query_params).to be(nil)
    end

    it "must default #test_all_query_params to nil" do
      expect(subject.test_all_query_params).to be(nil)
    end

    it "must default #test_header_names to nil" do
      expect(subject.test_header_names).to be(nil)
    end

    it "must default #test_cookie_params to nil" do
      expect(subject.test_cookie_params).to be(nil)
    end

    it "must default #test_all_cookie_params to nil" do
      expect(subject.test_all_cookie_params).to be(nil)
    end

    it "must default #test_form_params to nil" do
      expect(subject.test_form_params).to be(nil)
    end
  end

  describe "#option_parser" do
    before { subject.option_parser.parse(argv) }

    context "when the '--first' option is parsed" do
      let(:argv) { %w[--first] }

      it "must set #scan_mode to :first" do
        expect(subject.scan_mode).to eq(:first)
      end
    end

    context "when the '--all' option is parsed" do
      let(:argv) { %w[--all] }

      it "must set #scan_mode to :all" do
        expect(subject.scan_mode).to eq(:all)
      end
    end

    context "when the '--header \"Name: value\"' option is parsed" do
      let(:header_name)  { 'X-Foo' }
      let(:header_value) { 'bar'   }

      let(:argv) { ['--header', "#{header_name}: #{header_value}"] }

      it "must set #headers to a Hash" do
        expect(subject.headers).to be_kind_of(Hash)
      end

      it "must add the header name and value to #headers" do
        expect(subject.headers[header_name]).to eq(header_value)
      end
    end

    context "when the '--cookie \"...\"' option is parsed" do
      let(:cookie) { 'foo=bar; baz=qux' }

      let(:argv) { ['--cookie', cookie] }

      it "must set #raw_cookie" do
        expect(subject.raw_cookie).to eq(cookie)
      end
    end

    context "when the '--cookie-param name=value' option is parsed" do
      let(:param_name)  { 'foo' }
      let(:param_value) { 'bar' }

      let(:argv) { ['--cookie-param', "#{param_name}=#{param_value}"] }

      it "must set #cookie to a Ronin::Support::Network::HTTP::Cookie" do
        expect(subject.cookie).to be_kind_of(Ronin::Support::Network::HTTP::Cookie)
      end

      it "must add the param name and value to #cookie" do
        expect(subject.cookie[param_name]).to eq(param_value)
      end
    end

    context "when the '--referer <URL>' option is parsed" do
      let(:referer)  { 'https://example.com/' }
      let(:argv)     { ['--referer', referer] }

      it "must set #referer" do
        expect(subject.referer).to eq(referer)
      end
    end

    context "when the '--form-param name=value' option is parsed" do
      let(:param_name)  { 'foo' }
      let(:param_value) { 'bar' }

      let(:argv) { ['--form-param', "#{param_name}=#{param_value}"] }

      it "must set #form_data to a Hash" do
        expect(subject.form_data).to be_kind_of(Hash)
      end

      it "must add the param name and value to #form_data" do
        expect(subject.form_data[param_name]).to eq(param_value)
      end
    end

    context "when the '--test-query-param <name>' option is parsed" do
      let(:query_param) { 'id' }

      let(:argv) { ['--test-query-param', query_param] }

      it "must set #test_query_params to a Set" do
        expect(subject.test_query_params).to be_kind_of(Set)
      end

      it "must add the query param name to #test_query_params" do
        expect(subject.test_query_params).to include(query_param)
      end
    end

    context "when the '--test-all-query-param' option is parsed" do
      let(:argv) { %w[--test-all-query-param] }

      it "must set #test_all_query_params to true" do
        expect(subject.test_all_query_params).to be(true)
      end
    end

    context "when the '--test-header-name <name>' option is parsed" do
      let(:header_name) { 'X-Foo' }

      let(:argv) { ['--test-header-name', header_name] }

      it "must set #test_header_names to a Set" do
        expect(subject.test_header_names).to be_kind_of(Set)
      end

      it "must add the query param name to #test_header_names" do
        expect(subject.test_header_names).to include(header_name)
      end
    end

    context "when the '--test-cookie-param <name>' option is parsed" do
      let(:cookie_param) { 'session_id' }

      let(:argv) { ['--test-cookie-param', cookie_param] }

      it "must set #test_cookie_params to a Set" do
        expect(subject.test_cookie_params).to be_kind_of(Set)
      end

      it "must add the query param name to #test_cookie_params" do
        expect(subject.test_cookie_params).to include(cookie_param)
      end
    end

    context "when the '--test-all-cookie-param' option is parsed" do
      let(:argv) { %w[--test-all-cookie-param] }

      it "must set #test_all_cookie_params to true" do
        expect(subject.test_all_cookie_params).to be(true)
      end
    end

    context "when the '--test-form-param <name>' option is parsed" do
      let(:form_param) { 'id' }

      let(:argv) { ['--test-form-param', form_param] }

      it "must set #test_form_params to a Set" do
        expect(subject.test_form_params).to be_kind_of(Set)
      end

      it "must add the query param name to #test_form_params" do
        expect(subject.test_form_params).to include(form_param)
      end
    end
  end

  let(:url) { 'https://example.com/page.php?id=1' }

  describe "#run" do
    let(:url1) { 'https://example.com/page1' }
    let(:url2) { 'https://example.com/page2' }

    context "when given URL arguments" do
      let(:argv) { [url1, url2] }

      it "must call #process_url with each URL argument" do
        expect(subject).to receive(:process_url).with(url1)
        expect(subject).to receive(:process_url).with(url2)

        subject.run(*argv)
      end
    end

    context "when given the '--input FILE' option" do
      let(:tempfile) { Tempfile.new(['ronin-vulns-input-file', '.txt']) }

      before do
        tempfile.puts(url1)
        tempfile.puts(url2)
        tempfile.flush
      end

      let(:argv) { ['--input', tempfile.path] }
      before { subject.option_parser.parse(argv) }

      it "must read the FILE and pass each line to #process_url" do
        expect(subject).to receive(:process_url).with(url1)
        expect(subject).to receive(:process_url).with(url2)

        subject.run
      end
    end

    context "when given neither URL arguments or '--input FILE'" do
      it "must print an error and exit with -1" do
        expect(subject).to receive(:print_error).with("must specify URL(s) or --input")
        expect(subject).to receive(:exit).with(-1)

        subject.run
      end
    end
  end

  describe "#process_url" do
    context "when #scan_mode is :first" do
      it "must call #test_url with the given URL" do
        expect(subject).to receive(:test_url).with(url)

        subject.process_url(url)
      end

      context "and #test_url returns a WebVuln object" do
        let(:vuln) { double('first returned WebVuln') }

        it "must call #log_vuln with the WebVuln object" do
          expect(subject).to receive(:test_url).with(url).and_return(vuln)
          expect(subject).to receive(:log_vuln).with(vuln)

          subject.process_url(url)
        end
      end
    end

    context "when #scan_mode is :all" do
      let(:argv) { ['--all'] }
      before { subject.option_parser.parse(argv) }

      it "must call #scan_url with the given URL" do
        expect(subject).to receive(:scan_url).with(url)

        subject.process_url(url)
      end

      context "and #scan_url yields WebVuln objects" do
        let(:vuln1) { double('yielded WebVuln 1') }
        let(:vuln2) { double('yielded WebVuln 2') }

        it "must call #log_vuln with the yielded WebVuln objects" do
          expect(subject).to receive(:scan_url).with(url).and_yield(vuln1).and_yield(vuln2)
          expect(subject).to receive(:log_vuln).with(vuln1)
          expect(subject).to receive(:log_vuln).with(vuln2)

          subject.process_url(url)
        end
      end
    end

    context "when the given URL is an IP address" do
      let(:url) { "127.0.0.1" }

      it do
        expect(subject).to receive(:print_error).with(
          "URL must start with http:// or https://: #{url.inspect}"
        )

        expect {
          subject.process_url(url)
        }.to raise_error(SystemExit)
      end
    end

    context "when the given URL is a hostname" do
      let(:url) { "example.com" }

      it do
        expect(subject).to receive(:print_error).with(
          "URL must start with http:// or https://: #{url.inspect}"
        )

        expect {
          subject.process_url(url)
        }.to raise_error(SystemExit)
      end
    end

    context "when the given URL does not start with http:// or https://" do
      let(:url) { "foo://" }

      it do
        expect(subject).to receive(:print_error).with(
          "URL must start with http:// or https://: #{url.inspect}"
        )

        expect {
          subject.process_url(url)
        }.to raise_error(SystemExit)
      end
    end
  end

  describe "#scan_kwargs" do
    it "must return an empty Hash by default" do
      expect(subject.scan_kwargs).to eq({})
    end

    context "when #headers is set" do
      let(:header_name)  { 'X-Foo' }
      let(:header_value) { 'bar'   }

      let(:argv) { ['--header', "#{header_name}: #{header_value}"] }
      before { subject.option_parser.parse(argv) }

      it "must set the :headers key in the Hash" do
        expect(subject.scan_kwargs[:headers]).to eq(subject.headers)
      end
    end

    context "when #raw_cookie is set" do
      let(:cookie) { 'foo=bar; baz=qux' }

      let(:argv) { ['--cookie', cookie] }
      before { subject.option_parser.parse(argv) }

      it "must set the :cookie key in the Hash" do
        expect(subject.scan_kwargs[:cookie]).to eq(subject.raw_cookie)
      end
    end

    context "when #cookie is set" do
      let(:param_name)  { 'foo' }
      let(:param_value) { 'bar' }

      let(:argv) { ['--cookie-param', "#{param_name}=#{param_value}"] }
      before { subject.option_parser.parse(argv) }

      it "must set the :cookie key in the Hash" do
        expect(subject.scan_kwargs[:cookie]).to eq(subject.cookie)
      end
    end

    context "when #referer is set" do
      let(:referer)  { 'https://example.com/' }

      let(:argv)     { ['--referer', referer] }
      before { subject.option_parser.parse(argv) }

      it "must set the :referer key in the Hash" do
        expect(subject.scan_kwargs[:referer]).to eq(subject.referer)
      end
    end

    context "when #form_data is set" do
      let(:param_name)  { 'foo' }
      let(:param_value) { 'bar' }

      let(:argv) { ['--form-param', "#{param_name}=#{param_value}"] }
      before { subject.option_parser.parse(argv) }

      it "must set the :form_data key in the Hash" do
        expect(subject.scan_kwargs[:form_data]).to eq(subject.form_data)
      end
    end

    context "when #test_query_params is set" do
      let(:query_param) { 'id' }

      let(:argv) { ['--test-query-param', query_param] }
      before { subject.option_parser.parse(argv) }

      it "must set the :query_params key in the Hash" do
        expect(subject.scan_kwargs[:query_params]).to eq(subject.test_query_params)
      end
    end

    context "when #test_all_query_params is set" do
      let(:argv) { %w[--test-all-query-param] }
      before { subject.option_parser.parse(argv) }

      it "must set the :query_params key in the Hash to true" do
        expect(subject.scan_kwargs[:query_params]).to be(true)
      end
    end

    context "when #test_header_names is set" do
      let(:header_name) { 'X-Foo' }

      let(:argv) { ['--test-header-name', header_name] }
      before { subject.option_parser.parse(argv) }

      it "must set the :header_names key in the Hash" do
        expect(subject.scan_kwargs[:header_names]).to eq(subject.test_header_names)
      end
    end

    context "when #test_cookie_params is set" do
      let(:cookie_param) { 'session_id' }

      let(:argv) { ['--test-cookie-param', cookie_param] }
      before { subject.option_parser.parse(argv) }

      it "must set the :cookie_params key in the Hash" do
        expect(subject.scan_kwargs[:cookie_params]).to eq(subject.test_cookie_params)
      end
    end

    context "when #test_all_cookie_params is set" do
      let(:argv) { %w[--test-all-cookie-param] }
      before { subject.option_parser.parse(argv) }

      it "must set the :cookie_params key in the Hash to true" do
        expect(subject.scan_kwargs[:cookie_params]).to be(true)
      end
    end

    context "when #test_form_params is set" do
      let(:form_param) { 'id' }

      let(:argv) { ['--test-form-param', form_param] }
      before { subject.option_parser.parse(argv) }

      it "must set the :form_params key in the Hash" do
        expect(subject.scan_kwargs[:form_params]).to eq(subject.test_form_params)
      end
    end
  end

  describe "#scan_url" do
    it do
      expect {
        subject.scan_url(url)
      }.to raise_error(NotImplementedError,"#{described_class}#scan_url was not defined")
    end
  end

  describe "#test_url" do
    it do
      expect {
        subject.test_url(url)
      }.to raise_error(NotImplementedError,"#{described_class}#test_url was not defined")
    end
  end
end
