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

    it "must initialize #test_payload to a random N*M payload" do
      expect(subject.test_payload).to match(/\A\d+\*\d+\z/)
    end

    it "must initialize #test_result to the result value of #test_payload" do
      expect(test.test_result).to eq(eval(subject.test_payload).to_s)
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

      expect(test[0]).to match(/\A\d+\*\d+\z/)
      expect(test[1]).to eq(eval(test[0]).to_s)
    end

    it "must return a random test playload and result each time" do
      payloads = Array.new(3) { subject.random_test }

      expect(payloads.uniq.length).to be > 1
    end
  end

  let(:test_payload) { '7*7' }
  let(:test_result)  { '49'  }
  let(:test)         { [test_payload, test_result] }

  describe ".scan" do
    subject { described_class }

    let(:url)     { "https://example.com/page?foo=1&bar=2&baz=3" }
    context "when the escape: keyword argument is not given" do
      it "must scan the URL using every escape in #{described_class}::ESCAPES" do
        stub_request(:get,"https://example.com/page?bar=2&baz=3&foo=#{test_payload}")
        stub_request(:get,"https://example.com/page?bar=2&baz=3&foo={{#{test_payload}}}")
        stub_request(:get,"https://example.com/page?bar=2&baz=3&foo=${#{test_payload}}")
        stub_request(:get,"https://example.com/page?bar=2&baz=3&foo=${{#{test_payload}}}")
        stub_request(:get,"https://example.com/page?bar=2&baz=3&foo=%23{#{test_payload}}")
        stub_request(:get,"https://example.com/page?bar=2&baz=3&foo=<%= #{test_payload} %>")
        stub_request(:get,"https://example.com/page?bar=#{test_payload}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar={{#{test_payload}}}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar=${#{test_payload}}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar=${{#{test_payload}}}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar=%23{#{test_payload}}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar=<%= #{test_payload} %>&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar=2&baz=#{test_payload}&foo=1")
        stub_request(:get,"https://example.com/page?bar=2&baz={{#{test_payload}}}&foo=1")
        stub_request(:get,"https://example.com/page?bar=2&baz=${{#{test_payload}}}&foo=1")
        stub_request(:get,"https://example.com/page?bar=2&baz=${#{test_payload}}&foo=1")
        stub_request(:get,"https://example.com/page?bar=2&baz=%23{#{test_payload}}&foo=1")
        stub_request(:get,"https://example.com/page?bar=2&baz=<%= #{test_payload} %>&foo=1")

        subject.scan(url, test: test)

        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=3&foo=#{test_payload}")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=3&foo={{#{test_payload}}}")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=3&foo=${#{test_payload}}")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=3&foo=${{#{test_payload}}}")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=3&foo=%23{#{test_payload}}")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=3&foo=<%= #{test_payload} %>")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=#{test_payload}&baz=3&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar={{#{test_payload}}}&baz=3&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=${#{test_payload}}&baz=3&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=${{#{test_payload}}}&baz=3&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=%23{#{test_payload}}&baz=3&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=<%= #{test_payload} %>&baz=3&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=#{test_payload}&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz={{#{test_payload}}}&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=${{#{test_payload}}}&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=${#{test_payload}}&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=%23{#{test_payload}}&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=<%= #{test_payload} %>&foo=1")
      end
    end

    context "when the escape: keyword argument is given" do
      let(:escape) { subject::ESCAPES[1] }

      it "must scan the URL using only the given escape" do
        stub_request(:get,"https://example.com/page?bar=2&baz=3&foo={{#{test_payload}}}")
        stub_request(:get,"https://example.com/page?bar={{#{test_payload}}}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar=2&baz={{#{test_payload}}}&foo=1")

        subject.scan(url, escape: escape, test: test)

        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz=3&foo={{#{test_payload}}}")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar={{#{test_payload}}}&baz=3&foo=1")
        expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2&baz={{#{test_payload}}}&foo=1")
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
    let(:payload) { subject.encode_payload('/etc/passwd') }

    include_examples "Ronin::Vulns::Web#exploit examples"
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
      expect(subject).to receive(:exploit).with(subject.test_payload).and_return(response)
    end

    it "must call #exploit with #test_payload" do
      subject.vulnerable?
    end

    context "when the response contains #test_result" do
      let(:response_body) do
        <<~HTML
        <html>
          <body>
            <p>example content</p>
            <p>#{test_result}content</p>
            <p>more content</p>
          </body>
        </html>
        HTML
      end

      it "must return true" do
        expect(subject.vulnerable?).to be_truthy
      end
    end

    context "when the response does not contain #test_result" do
      it "must return true" do
        expect(subject.vulnerable?).to be_falsy
      end
    end
  end
end
