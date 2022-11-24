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

    context "when given `lfi: false`" do
      it "must not call LFI.scan" do
        expect(Ronin::Vulns::LFI).to_not receive(:scan)
        expect(Ronin::Vulns::RFI).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::SQLI).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::SSTI).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::ReflectedXSS).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::OpenRedirect).to receive(:scan).with(url).and_return([])

        subject.scan(url, lfi: false)
      end
    end

    context "when given `rfi: false`" do
      it "must not call RFI.scan" do
        expect(Ronin::Vulns::LFI).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::RFI).to_not receive(:scan)
        expect(Ronin::Vulns::SQLI).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::SSTI).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::ReflectedXSS).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::OpenRedirect).to receive(:scan).with(url).and_return([])

        subject.scan(url, rfi: false)
      end
    end

    context "when given `sqli: false`" do
      it "must not call SQLI.scan" do
        expect(Ronin::Vulns::LFI).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::RFI).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::SQLI).to_not receive(:scan)
        expect(Ronin::Vulns::SSTI).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::ReflectedXSS).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::OpenRedirect).to receive(:scan).with(url).and_return([])

        subject.scan(url, sqli: false)
      end
    end

    context "when given `ssti: false`" do
      it "must not call SSTI.scan" do
        expect(Ronin::Vulns::LFI).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::RFI).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::SQLI).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::SSTI).to_not receive(:scan)
        expect(Ronin::Vulns::ReflectedXSS).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::OpenRedirect).to receive(:scan).with(url).and_return([])

        subject.scan(url, ssti: false)
      end
    end

    context "when given `reflected_xss: false`" do
      it "must not call ReflectedXSS.scan" do
        expect(Ronin::Vulns::LFI).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::RFI).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::SQLI).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::SSTI).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::ReflectedXSS).to_not receive(:scan)
        expect(Ronin::Vulns::OpenRedirect).to receive(:scan).with(url).and_return([])

        subject.scan(url, reflected_xss: false)
      end
    end

    context "when given `open_redirect: false`" do
      it "must not call OpenRedirect.scan" do
        expect(Ronin::Vulns::LFI).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::RFI).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::SQLI).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::SSTI).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::ReflectedXSS).to receive(:scan).with(url).and_return([])
        expect(Ronin::Vulns::OpenRedirect).to_not receive(:scan)

        subject.scan(url, open_redirect: false)
      end
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
