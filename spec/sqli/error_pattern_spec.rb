require 'spec_helper'
require 'ronin/vulns/sqli/error_pattern'

describe Ronin::Vulns::SQLI::ErrorPattern do
  let(:regexps) do
    [
      /PostgreSQL.*ERROR/,
      /Warning.*\Wpg_/,
      /valid PostgreSQL result/,
      /Npgsql\./,
      /PG::SyntaxError:/,
      /org\.postgresql\.util\.PSQLException/,
      /ERROR:\s\ssyntax error at or near/,
      /ERROR: parser: parse error at or near/,
      /PostgreSQL query failed/,
      /org\.postgresql\.jdbc/,
      %r{Pdo[\./_\\]Pgsql},
      /PSQLException/
    ]
  end
  let(:regexp) { Regexp.union(regexps) }

  subject { described_class.new(regexp) }

  describe "#initialize" do
    it "must set #regexp" do
      expect(subject.regexp).to eq(regexp)
    end
  end

  describe ".[]" do
    subject { described_class }

    it "must return a #{described_class}" do
      expect(subject[*regexps]).to be_kind_of(described_class)
    end

    it "must union together the given Regexps and set #regexp" do
      expect(subject[*regexps].regexp).to eq(regexp)
    end
  end

  describe "#match" do
    context "when the #regexp matches the response body" do
      let(:error) { "PostgreSQL bla bla bla ERROR" }
      let(:response_body) do
        <<~HTML
          <html>
            <body>
              <p>bla bla bla</p>
              #{error} bla bla bla
              <p>bla bla bla</p>
            </body>
          </html>
        HTML
      end

      it "must return MatchData" do
        expect(subject.match(response_body)).to be_kind_of(MatchData)
      end

      it "must match the given response body against #regexp" do
        expect(subject.match(response_body)[0]).to eq(error)
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
      let(:error) { "PostgreSQL bla bla bla ERROR" }
      let(:response_body) do
        <<~HTML
          <html>
            <body>
              <p>bla bla bla</p>
              #{error} bla bla bla
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
