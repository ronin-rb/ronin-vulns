require 'spec_helper'
require 'ronin/vulns/lfi/test_file'

describe Ronin::Vulns::LFI::TestFile do
  let(:path)   { '/etc/foo' }
  let(:regexp) { /foo\nbar\nbaz\n/ }

  subject { described_class.new(path,regexp) }

  describe "#initialize" do
    it "must set #path" do
      expect(subject.path).to eq(path)
    end

    it "must set #regexp" do
      expect(subject.regexp).to eq(regexp)
    end
  end

  describe "#match" do
    context "when the #regexp matches the response body" do
      let(:file) { "foo\nbar\nbaz\n" }
      let(:response_body) do
        <<~HTML
        <html>
          <body>
            <p>bla bla bla</p>
            #{file}
            <p>bla bla bla</p>
          </body>
        </html>
        HTML
      end

      it "must return MatchData" do
        expect(subject.match(response_body)).to be_kind_of(MatchData)
      end

      it "must match the given response body against #regexp" do
        expect(subject.match(response_body)[0]).to eq(file)
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

  describe "#=~" do
    context "when the #regexp matches the response body" do
      let(:file) { "foo\nbar\nbaz\n" }
      let(:response_body) do
        <<~HTML
        <html>
          <body>
            <p>bla bla bla</p>
            #{file}
            <p>bla bla bla</p>
          </body>
        </html>
        HTML
      end

      it "must return the index of the match" do
        expect(subject =~ response_body).to eq(response_body.index(regexp))
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
        expect(subject =~ response_body).to be(nil)
      end
    end
  end
end
