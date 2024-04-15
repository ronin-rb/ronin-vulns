require 'spec_helper'
require 'web_vuln_examples'
require 'ronin/vulns/ssti'

require 'webmock/rspec'

describe Ronin::Vulns::SSTI do
  describe ".vuln_type" do
    subject { described_class }

    it "must return :ssti" do
      expect(subject.vuln_type).to eq(:ssti)
    end
  end

  describe "#initialize" do
    include_examples "Ronin::Vulns::WebVuln#initialize examples"

    it "must default #escape_type to nil" do
      expect(subject.escape_type).to be(nil)
    end

    it "must default #escape to nil" do
      expect(subject.escape).to be(nil)
    end

    it "must initialize #test_expr to a random N*M #{described_class}::TestExpression" do
      expect(subject.test_expr).to be_kind_of(described_class::TestExpression)
      expect(subject.test_expr.string).to match(/\A\d+\*\d+\z/)
      expect(subject.test_expr.result).to eq(eval(subject.test_expr.string).to_s)
    end

    context "when the escape: keyword argument is given" do
      subject { described_class.new(url, escape: escape) }

      context "and it's a Symbol" do
        let(:escape) { :double_curly_braces }

        it "must set #escape_type to the escape Symbol" do
          expect(subject.escape_type).to eq(escape)
        end

        it "must resolve the Symbol name and set #escape to the value in #{described_class}::ESCAPES" do
          expect(subject.escape).to be(described_class::ESCAPES.fetch(escape))
        end
      end

      context "and it's a Proc" do
        let(:escape) do
          ->(expr) { "{#{expr}}" }
        end

        it "must set #escape_type to :custom" do
          expect(subject.escape_type).to be(:custom)
        end

        it "must set #escape" do
          expect(subject.escape).to be(escape)
        end
      end

      context "when it's nil" do
        let(:escape) { nil }

        it "must set #escape_type to nil" do
          expect(subject.escape_type).to be(nil)
        end

        it "must set #escape" do
          expect(subject.escape).to be(nil)
        end
      end

      context "when it's another kind of Object" do
        let(:escape) { Object.new }

        it do
          expect {
            described_class.new(url, escape: escape)
          }.to raise_error(ArgumentError,"invalid escape type, must be a Symbol, Proc, or nil: #{escape.inspect}")
        end
      end
    end
  end

  describe ".random_test" do
    subject { described_class }

    it "must return a random N*M String and the result of N*M" do
      test_expr = subject.random_test

      expect(test_expr.string).to match(/\A\d+\*\d+\z/)
      expect(test_expr.result).to eq(eval(test_expr.string).to_s)
    end

    it "must return a random test playload and result each time" do
      payloads = Array.new(3) { subject.random_test }

      expect(payloads.uniq.length).to be > 1
    end
  end

  let(:test_string) { '7*7' }
  let(:test_result) { '49'  }
  let(:test_expr) do
    described_class::TestExpression.new(test_string,test_result)
  end

  describe ".test_param" do
    subject { described_class }

    let(:url)         { "https://example.com/page?foo=1&bar=2&baz=3" }
    let(:query_param) { 'bar' }
    let(:http)        { Ronin::Support::Network::HTTP.connect_uri(url) }

    it "must test the URL and param using using every escape in #{described_class}::ESCAPES" do
      stub_request(:get,"https://example.com/page?bar=#{test_string}&baz=3&foo=1")
      stub_request(:get,"https://example.com/page?bar={{#{test_string}}}&baz=3&foo=1")
      stub_request(:get,"https://example.com/page?bar=${#{test_string}}&baz=3&foo=1")
      stub_request(:get,"https://example.com/page?bar=${{#{test_string}}}&baz=3&foo=1")
      stub_request(:get,"https://example.com/page?bar=%23{#{test_string}}&baz=3&foo=1")
      stub_request(:get,"https://example.com/page?bar=<%= #{test_string} %>&baz=3&foo=1")

      subject.test_param(url, query_param: query_param,
                              test_expr:   test_expr,
                              http:        http)

      expect(WebMock).to have_requested(:get,"https://example.com/page?bar=#{test_string}&baz=3&foo=1")
      expect(WebMock).to have_requested(:get,"https://example.com/page?bar={{#{test_string}}}&baz=3&foo=1")
      expect(WebMock).to have_requested(:get,"https://example.com/page?bar=${#{test_string}}&baz=3&foo=1")
      expect(WebMock).to have_requested(:get,"https://example.com/page?bar=${{#{test_string}}}&baz=3&foo=1")
      expect(WebMock).to have_requested(:get,"https://example.com/page?bar=%23{#{test_string}}&baz=3&foo=1")
      expect(WebMock).to have_requested(:get,"https://example.com/page?bar=<%= #{test_string} %>&baz=3&foo=1")
    end

    context "and when one of the responses indicates a SSTI vulnerability" do
      let(:vulnerable_response_body) do
        <<~HTML
          <html>
            <body>
              <p>example content</p>
              <p>#{test_expr.result}content</p>
              <p>more content</p>
            </body>
          </html>
        HTML
      end

      it "must stop enumerating through the escapes in #{described_class}::ESCAPES,  and return a vulnerable #{described_class} object" do
        stub_request(:get,"https://example.com/page?bar=#{test_string}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar={{#{test_string}}}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar=${#{test_string}}&baz=3&foo=1").to_return(status: 200, body: vulnerable_response_body)

        vuln = subject.test_param(url, query_param: query_param,
                                       test_expr:   test_expr,
                                       http:        http)

        expect(vuln).to be_kind_of(described_class)
        expect(vuln.query_param).to eq(query_param)
        expect(vuln.escape_type).to eq(:dollar_curly_braces)
      end
    end

    context "but none of the responses indicate a SSTI vulnerability" do
      it "must return nil" do
        stub_request(:get,"https://example.com/page?bar=#{test_string}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar={{#{test_string}}}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar=${#{test_string}}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar=${{#{test_string}}}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar=%23{#{test_string}}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar=<%= #{test_string} %>&baz=3&foo=1")

        vuln = subject.test_param(url, query_param: query_param,
                                       test_expr:   test_expr,
                                       http:        http)

        expect(vuln).to be(nil)
      end
    end

    context "when the escape: keyword argument is given" do
      context "and it's a Symbol" do
        let(:escape) { :double_curly_braces }

        it "must test the URL and param using only the given escape type" do
          stub_request(:get,"https://example.com/page?bar={{#{test_string}}}&baz=3&foo=1")

          subject.test_param(url, query_param: query_param,
                                  escape:      escape,
                                  test_expr:   test_expr,
                                  http:        http)

          expect(WebMock).to have_requested(:get,"https://example.com/page?bar={{#{test_string}}}&baz=3&foo=1")
        end
      end

      context "and it's a Proc" do
        let(:escape) do
          ->(expr) { "{#{expr}}" }
        end

        it "must test the URL and param using only the given escape Proc" do
          stub_request(:get,"https://example.com/page?bar={#{test_string}}&baz=3&foo=1")

          subject.test_param(url, query_param: query_param,
                                  escape:      escape,
                                  test_expr:   test_expr,
                                  http:        http)

          expect(WebMock).to have_requested(:get,"https://example.com/page?bar={#{test_string}}&baz=3&foo=1")
        end
      end

      context "and it's an Array" do
        let(:escape) do
          [:double_curly_braces, :dollar_curly_braces]
        end

        it "must scan the URL and param using the escape types" do
          stub_request(:get,"https://example.com/page?bar={{#{test_string}}}&baz=3&foo=1")
          stub_request(:get,"https://example.com/page?bar=${#{test_string}}&baz=3&foo=1")

          subject.test_param(url, query_param: query_param,
                                  escape:      escape,
                                  test_expr:   test_expr,
                                  http:        http)

          expect(WebMock).to have_requested(:get,"https://example.com/page?bar={{#{test_string}}}&baz=3&foo=1")
          expect(WebMock).to have_requested(:get,"https://example.com/page?bar=${#{test_string}}&baz=3&foo=1")
        end
      end
    end
  end

  let(:query_param) { 'bar' }
  let(:url)         { "https://example.com/page?foo=1&bar=2&baz=3" }

  subject do
    described_class.new(url, query_param: query_param,
                             test_expr:   test_expr)
  end

  describe "#encode_payload" do
    let(:payload) { '7*7' }

    context "when #escape is set" do
      let(:escape) do
        ->(payload) { "{{#{payload}}}" }
      end

      subject { described_class.new(url, escape: escape) }

      it "must escape the payload using #escape" do
        expect(subject.encode_payload(payload)).to eq(escape.call(payload))
      end
    end

    context "when #escape is nil" do
      it "must send the payload without any escaping" do
        expect(subject.encode_payload(payload)).to eq(payload)
      end
    end
  end

  describe "#vulnerable?" do
    let(:request_url) { subject.exploit_url(subject.test_script_url) }

    let(:response_body) do
      <<~HTML
        <html>
          <body>
            <p>example content</p>
            <p>included content</p>
            <p>more content</p>
          </body>
        </html>
      HTML
    end
    let(:response) { double('Net::HTTPResponse', body: response_body) }

    before do
      expect(subject).to receive(:exploit).with(subject.test_expr.string).and_return(response)
    end

    it "must call #exploit with #test.string" do
      subject.vulnerable?
    end

    context "when the response contains #test_expr.result" do
      let(:response_body) do
        <<~HTML
          <html>
            <body>
              <p>example content</p>
              <p>#{test_expr.result}content</p>
              <p>more content</p>
            </body>
          </html>
        HTML
      end

      it "must return true" do
        expect(subject.vulnerable?).to be_truthy
      end
    end

    context "when the response does not contain #test_expr.result" do
      it "must return false" do
        expect(subject.vulnerable?).to be_falsy
      end
    end
  end
end
