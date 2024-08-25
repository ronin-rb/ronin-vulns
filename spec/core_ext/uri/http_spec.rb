require 'spec_helper'
require 'ronin/vulns/core_ext/uri/http'

describe URI::HTTP do
  let(:url) { 'https://example.com/' }

  subject { URI(url) }

  let(:web_vuln1) { Ronin::Vulns::LFI.new(url)  }
  let(:web_vuln2) { Ronin::Vulns::SQLI.new(url) }

  describe "#vulns" do
    context "when URI contains vulnerabilities" do
      it "must return array with vulnerabilities" do
        expect(Ronin::Vulns::URLScanner).to receive(:scan).and_return([web_vuln1, web_vuln2])

        expect(subject.vulns).to match_array([web_vuln1, web_vuln2])
      end
    end

    context "when URI does not contain any vulnerabilities" do
      it "must return an empty array" do
        expect(Ronin::Vulns::URLScanner).to receive(:scan).and_return([])

        expect(subject.vulns).to be_empty
      end
    end
  end

  describe "#has_vulns?" do
    context "when URI contains vulnerabilities" do
      it "must return true" do
        expect(Ronin::Vulns::URLScanner).to receive(:test).and_return(web_vuln1)

        expect(subject.has_vulns?).to be(true)
      end
    end

    context "when URI does not contain any vulnerabilities" do
      it "must return false" do
        expect(Ronin::Vulns::URLScanner).to receive(:test).and_return(nil)

        expect(subject.has_vulns?).to be(false)
      end
    end
  end
end
