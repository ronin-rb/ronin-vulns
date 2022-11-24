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

    it "must default #escape to nil" do
      expect(subject.escape).to be(nil)
    end

    it "must initialize #test to a random N*M #{described_class}::TestExpression" do
      expect(subject.test).to be_kind_of(described_class::TestExpression)
      expect(subject.test.string).to match(/\A\d+\*\d+\z/)
      expect(subject.test.result).to eq(eval(subject.test.string).to_s)
    end

    context "when the escape: keyword argument is given" do
      let(:escape) { described_class::ESCAPES[1] }

      subject { described_class.new(url, escape: escape) }

      it "must set #escape" do
        expect(subject.escape).to be(escape)
      end
    end
  end

  describe ".random_test" do
    subject { described_class }

    it "must return a random N*M String and the result of N*M" do
      test = subject.random_test

      expect(test.string).to match(/\A\d+\*\d+\z/)
      expect(test.result).to eq(eval(test.string).to_s)
    end

    it "must return a random test playload and result each time" do
      payloads = Array.new(3) { subject.random_test }

      expect(payloads.uniq.length).to be > 1
    end
  end

  let(:test_string) { '7*7' }
  let(:test_result) { '49'  }
  let(:test) do
    described_class::TestExpression.new(test_string,test_result)
  end

  describe ".scan" do
    subject { described_class }

    let(:url)     { "https://example.com/page?foo=1&bar=2&baz=3" }
    context "when the escape: keyword argument is not given" do
      it "must scan the URL using every escape in #{described_class}::ESCAPES" do
        stub_request(:get,"https://example.com/page?bar=2&baz=3&foo=#{test_string}")
        stub_request(:get,"https://example.com/page?bar=2&baz=3&foo={{#{test_string}}}")
        stub_request(:get,"https://example.com/page?bar=2&baz=3&foo=${#{test_string}}")
        stub_request(:get,"https://example.com/page?bar=2&baz=3&foo=${{#{test_string}}}")
        stub_request(:get,"https://example.com/page?bar=2&baz=3&foo=%23{#{test_string}}")
        stub_request(:get,"https://example.com/page?bar=2&baz=3&foo=<%= #{test_string} %>")
        stub_request(:get,"https://example.com/page?bar=#{test_string}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar={{#{test_string}}}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar=${#{test_string}}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar=${{#{test_string}}}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar=%23{#{test_string}}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar=<%= #{test_string} %>&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar=2&baz=#{test_string}&foo=1")
        stub_request(:get,"https://example.com/page?bar=2&baz={{#{test_string}}}&foo=1")
        stub_request(:get,"https://example.com/page?bar=2&baz=${{#{test_string}}}&foo=1")
        stub_request(:get,"https://example.com/page?bar=2&baz=${#{test_string}}&foo=1")
        stub_request(:get,"https://example.com/page?bar=2&baz=%23{#{test_string}}&foo=1")
        stub_request(:get,"https://example.com/page?bar=2&baz=<%= #{test_string} %>&foo=1")

        subject.scan(url, test: test)

        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=3&foo=#{test_string}")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=3&foo={{#{test_string}}}")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=3&foo=${#{test_string}}")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=3&foo=${{#{test_string}}}")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=3&foo=%23{#{test_string}}")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=3&foo=<%= #{test_string} %>")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=#{test_string}&baz=3&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar={{#{test_string}}}&baz=3&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=${#{test_string}}&baz=3&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=${{#{test_string}}}&baz=3&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=%23{#{test_string}}&baz=3&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=<%= #{test_string} %>&baz=3&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=#{test_string}&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz={{#{test_string}}}&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=${{#{test_string}}}&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=${#{test_string}}&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=%23{#{test_string}}&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=<%= #{test_string} %>&foo=1")
      end
    end

    context "when the escape: keyword argument is given" do
      let(:escape) { subject::ESCAPES[1] }

      it "must scan the URL using only the given escape" do
        stub_request(:get,"https://example.com/page?bar=2&baz=3&foo={{#{test_string}}}")
        stub_request(:get,"https://example.com/page?bar={{#{test_string}}}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar=2&baz={{#{test_string}}}&foo=1")

        subject.scan(url, escape: escape, test: test)

        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=3&foo={{#{test_string}}}")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar={{#{test_string}}}&baz=3&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz={{#{test_string}}}&foo=1")
      end
    end
  end

  let(:query_param) { 'bar' }
  let(:url)         { "https://example.com/page?foo=1&bar=2&baz=3" }

  subject { described_class.new(url, query_param: query_param, test: test) }

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

  describe "#exploit" do
    let(:payload)         { '/etc/passwd' }
    let(:escaped_payload) { subject.encode_payload(payload) }

    include_examples "Ronin::Vulns::WebVuln#exploit examples"
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
      expect(subject).to receive(:exploit).with(subject.test.string).and_return(response)
    end

    it "must call #exploit with #test.string" do
      subject.vulnerable?
    end

    context "when the response contains #test.result" do
      let(:response_body) do
        <<~HTML
        <html>
          <body>
            <p>example content</p>
            <p>#{test.result}content</p>
            <p>more content</p>
          </body>
        </html>
        HTML
      end

      it "must return true" do
        expect(subject.vulnerable?).to be_truthy
      end
    end

    context "when the response does not contain #test.result" do
      it "must return false" do
        expect(subject.vulnerable?).to be_falsy
      end
    end
  end
end
