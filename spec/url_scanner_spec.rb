require 'spec_helper'
require 'ronin/vulns/url_scanner'

describe Ronin::Vulns::URLScanner do
  let(:url) { "https://example.com/page?id=1" }

  let(:web_vuln1) { Ronin::Vulns::LFI.new(url)  }
  let(:web_vuln2) { Ronin::Vulns::SQLI.new(url) }

  describe ".scan" do
    it "must call LFI.scan, RFI.scan, SQLI.scan, SSTI.scan, ReflectedXSS.scan, and OpenRedirect.scan" do
      expect(Ronin::Vulns::LFI).to receive(:scan).with(url).and_return([])
      expect(Ronin::Vulns::RFI).to receive(:scan).with(url).and_return([])
      expect(Ronin::Vulns::SQLI).to receive(:scan).with(url).and_return([])
      expect(Ronin::Vulns::SSTI).to receive(:scan).with(url).and_return([])
      expect(Ronin::Vulns::ReflectedXSS).to receive(:scan).with(url).and_return([])
      expect(Ronin::Vulns::OpenRedirect).to receive(:scan).with(url).and_return([])

      subject.scan(url)
    end

    context "when web vulnerabilites are discovered in the URL" do
      context "and when a block is given" do
        before do
          expect(Ronin::Vulns::LFI).to receive(:scan).with(url).and_yield(web_vuln1).and_return([web_vuln1])
          expect(Ronin::Vulns::RFI).to receive(:scan).with(url).and_return([])
          expect(Ronin::Vulns::SQLI).to receive(:scan).with(url).and_yield(web_vuln2).and_return([web_vuln2])
          expect(Ronin::Vulns::SSTI).to receive(:scan).with(url).and_return([])
          expect(Ronin::Vulns::ReflectedXSS).to receive(:scan).with(url).and_return([])
          expect(Ronin::Vulns::OpenRedirect).to receive(:scan).with(url).and_return([])
        end

        it "must yield each web vulnerability instance to the given block"  do
          expect { |b|
            subject.scan(url,&b)
          }.to yield_successive_args(
            web_vuln1,
            web_vuln2
          )
        end

        it "must also return an array of the discovered web vulnerability instances" do
          expect(subject.scan(url) { |vuln| }).to eq(
            [
              web_vuln1,
              web_vuln2
            ]
          )
        end
      end

      context "but no block is given" do
        before do
          expect(Ronin::Vulns::LFI).to receive(:scan).with(url).and_return([web_vuln1])
          expect(Ronin::Vulns::RFI).to receive(:scan).with(url).and_return([])
          expect(Ronin::Vulns::SQLI).to receive(:scan).with(url).and_return([web_vuln2])
          expect(Ronin::Vulns::SSTI).to receive(:scan).with(url).and_return([])
          expect(Ronin::Vulns::ReflectedXSS).to receive(:scan).with(url).and_return([])
          expect(Ronin::Vulns::OpenRedirect).to receive(:scan).with(url).and_return([])
        end

        it "must return an array of the discovered web vulnerability instances" do
          expect(subject.scan(url)).to eq(
            [
              web_vuln1,
              web_vuln2
            ]
          )
        end
      end
    end

    context "but no web vulnerabilities were found" do
      before do
        expect(Ronin::Vulns::LFI).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::RFI).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::SQLI).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::SSTI).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::ReflectedXSS).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::OpenRedirect).to receive(:scan).with(url).and_return([])
      end

      context "and a block is given" do
        it "must not yield any web vulnerability instance to the given block"  do
          expect { |b|
            subject.scan(url,&b)
          }.to_not yield_control
        end

        it "must also return an empty Array" do
          expect(subject.scan(url) { |vuln| }).to eq([])
        end
      end

      context "but no block is given" do
        it "must return an empty Array" do
          expect(subject.scan(url)).to eq([])
        end
      end
    end
  end

  describe ".test" do
    it "must call .scan and return the first vulnerable instance" do
      expect(subject).to receive(:scan).with(url).and_yield(web_vuln1).and_yield(web_vuln2)

      expect(subject.test(url)).to eq(web_vuln1)
    end

    context "when .scan does not yield any vulnerabiltieis" do
      it "must return nil" do
        expect(subject).to receive(:scan).with(url)

        expect(subject.test(url)).to be(nil)
      end
    end
  end
end
