require 'spec_helper'
require 'web_vuln_examples'
require 'ronin/vulns/ssti'

require 'webmock/rspec'

describe Ronin::Vulns::SSTI do
  describe "#initialize" do
    include_examples "Ronin::Vulns::Web#initialize examples"

    it "must default #escape to nil" do
      expect(subject.escape).to be(nil)
    end

    context "when the escape: keyword argument is given" do
      let(:escape) { described_class::ESCAPES[1] }

      subject { described_class.new(url, escape: escape) }

      it "must set #escape" do
        expect(subject.escape).to be(escape)
      end
    end
  end

  describe ".scan" do
    subject { described_class }

    let(:url)     { "https://example.com/page?foo=1&bar=2&baz=3" }
    let(:payload) { described_class::TEST_PAYLOAD }

    context "when the escape: keyword argument is not given" do
      it "must scan the URL using every escape in #{described_class}::ESCAPES" do
        stub_request(:get,"https://example.com/page?bar=2&baz=3&foo=#{payload}")
        stub_request(:get,"https://example.com/page?bar=2&baz=3&foo={{#{payload}}}")
        stub_request(:get,"https://example.com/page?bar=2&baz=3&foo=${#{payload}}")
        stub_request(:get,"https://example.com/page?bar=2&baz=3&foo=${{#{payload}}}")
        stub_request(:get,"https://example.com/page?bar=2&baz=3&foo=%23{#{payload}}")
        stub_request(:get,"https://example.com/page?bar=2&baz=3&foo=<%= #{payload} %>")
        stub_request(:get,"https://example.com/page?bar=#{payload}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar={{#{payload}}}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar=${#{payload}}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar=${{#{payload}}}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar=%23{#{payload}}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar=<%= #{payload} %>&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar=2&baz=#{payload}&foo=1")
        stub_request(:get,"https://example.com/page?bar=2&baz={{#{payload}}}&foo=1")
        stub_request(:get,"https://example.com/page?bar=2&baz=${{#{payload}}}&foo=1")
        stub_request(:get,"https://example.com/page?bar=2&baz=${#{payload}}&foo=1")
        stub_request(:get,"https://example.com/page?bar=2&baz=%23{#{payload}}&foo=1")
        stub_request(:get,"https://example.com/page?bar=2&baz=<%= #{payload} %>&foo=1")

        subject.scan(url)

        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=3&foo=#{payload}")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=3&foo={{#{payload}}}")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=3&foo=${#{payload}}")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=3&foo=${{#{payload}}}")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=3&foo=%23{#{payload}}")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=3&foo=<%= #{payload} %>")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=#{payload}&baz=3&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar={{#{payload}}}&baz=3&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=${#{payload}}&baz=3&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=${{#{payload}}}&baz=3&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=%23{#{payload}}&baz=3&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=<%= #{payload} %>&baz=3&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=#{payload}&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz={{#{payload}}}&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=${{#{payload}}}&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=${#{payload}}&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=%23{#{payload}}&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=<%= #{payload} %>&foo=1")
      end
    end

    context "when the escape: keyword argument is given" do
      let(:escape) { subject::ESCAPES[1] }

      it "must scan the URL using only the given escape" do
        stub_request(:get,"https://example.com/page?bar=2&baz=3&foo={{#{payload}}}")
        stub_request(:get,"https://example.com/page?bar={{#{payload}}}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar=2&baz={{#{payload}}}&foo=1")

        subject.scan(url, escape: escape)

        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=3&foo={{#{payload}}}")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar={{#{payload}}}&baz=3&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz={{#{payload}}}&foo=1")
      end
    end
  end

  let(:query_param) { 'bar' }
  let(:url)         { "https://example.com/page?foo=1&bar=2&baz=3" }

  subject { described_class.new(url, query_param: query_param) }

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
    let(:payload) { subject.encode_payload('/etc/passwd') }

    include_examples "Ronin::Vulns::Web#exploit examples"
  end

  describe "TEST_PAYLOAD" do
    it { expect(described_class::TEST_PAYLOAD).to eq('12345*12345') }
  end
  
  describe "TEST_EXPECTED_VALUE" do
    it "must equal the result of the TEST_VALUE" do
      expect(described_class::TEST_EXPECTED_VALUE).to eq(
        eval(described_class::TEST_PAYLOAD).to_s
      )
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
      expect(subject).to receive(:exploit).with(described_class::TEST_PAYLOAD).and_return(response)
    end

    it "must call #exploit with #{described_class}::TEST_PAYLOAD" do
      subject.vulnerable?
    end

    context "when the response contains #{described_class}::TEST_EXPECTED_VALUE" do
      let(:response_body) do
        <<~HTML
        <html>
          <body>
            <p>example content</p>
            <p>#{described_class::TEST_EXPECTED_VALUE}content</p>
            <p>more content</p>
          </body>
        </html>
        HTML
      end

      it "must return true" do
        expect(subject.vulnerable?).to be_truthy
      end
    end

    context "when the response does not contain #{described_class}::TEST_EXPECTED_VALUE" do
      it "must return true" do
        expect(subject.vulnerable?).to be_falsy
      end
    end
  end
end
