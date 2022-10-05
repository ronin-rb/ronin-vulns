require 'spec_helper'
require 'ronin/vulns/reflected_xss/test_string'

describe Ronin::Vulns::ReflectedXSS::TestString do
  let(:string) { "abc" }
  let(:regexp) { /(a)(b)(c)/ }

  subject { described_class.new(string,regexp) }

  describe "#initialize" do
    it "must set #string" do
      expect(subject.string).to eq(string)
    end

    it "must set #regexp" do
      expect(subject.regexp).to eq(regexp)
    end
  end

  describe ".build" do
    let(:string) { "'\" /><&" }

    subject { described_class.build(string) }

    it "must return a new #{described_class}" do
      expect(subject).to be_kind_of(described_class)
    end

    it "must set #string" do
      expect(subject.string).to eq(string)
    end

    it "must build a Regexp that captures the characters but ignores their HTML/URI escaped versions" do
      expect(subject.regexp).to eq(
        /(?:(')|%27|&\#39;|\\')?(?:(")|%22|&quot;|\\")?(?:(\ )|\+|%20|&nbsp;)?(?:(\/)|%2F)?(?:(>)|%3E|&gt;)?(?:(<)|%3C|&lt;)?(?:(&)|%26|&amp;)?/
      )
    end
  end

  describe "#wrap" do
    let(:prefix) { 'ABC' }
    let(:suffix) { 'XYZ' }

    subject { super().wrap(prefix,suffix) }

    it "must return a new #{described_class}" do
      expect(subject).to be_kind_of(described_class)
    end

    it "must prepend the prefix and append the suffix to the #string" do
      expect(subject.string).to eq("#{prefix}#{string}#{suffix}")
    end

    it "must prepend the prefix and append the suffix to the #regexp" do
      expect(subject.regexp).to eq(/#{prefix}#{regexp}#{suffix}/)
    end

    context "when the prefix contains Regexp special characters" do
      let(:prefix)  { "ABC*CDE"  }
      let(:escaped) { 'ABC\*CDE' }

      it "must escape the prefix before prepending it to the #regexp" do
        expect(subject.regexp).to eq(/#{escaped}#{regexp}#{suffix}/)
      end
    end

    context "when the suffix contains Regexp special characters" do
      let(:suffix)  { "ABC*CDE"  }
      let(:escaped) { 'ABC\*CDE' }

      it "must escape the prefix before prepending it to the #regexp" do
        expect(subject.regexp).to eq(/#{prefix}#{regexp}#{escaped}/)
      end
    end
  end

  describe "#match" do
    let(:prefix) { 'ABC' }
    let(:suffix) { 'XYZ' }

    subject { super().wrap(prefix,suffix) }

    context "when the #regexp matches the response body" do
      let(:response_body) do
        <<~HTML
        <html>
          <body>
            <p>bla bla bla</p>
            ABCabcXYZ
            <p>bla bla bla</p>
          </body>
        </html>
        HTML
      end

      it "must return MatchData" do
        expect(subject.match(response_body)).to be_kind_of(MatchData)
      end

      it "must match the given response body against #regexp" do
        match = subject.match(response_body)

        expect(match[0]).to eq('ABCabcXYZ')
        expect(match[1]).to eq('a')
        expect(match[2]).to eq('b')
        expect(match[3]).to eq('c')
      end
    end

    context "when the #regexp does not match the response body" do
      let(:response_body) do
        <<~HTML
        <html>
          <body>
            <p>bla bla bla</p>
            <p>bla bla bla</p>
            <p>bla bla bla</p>
          </body>
        </html>
        HTML
      end

      it "must return nil" do
        expect(subject.match(response_body)).to be(nil)
      end
    end
  end

  describe "#to_s" do
    it "must return the string" do
      expect(subject.to_s).to eq(string)
    end
  end
end
