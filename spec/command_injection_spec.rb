require 'spec_helper'
require 'web_vuln_examples'
require 'ronin/vulns/command_injection'

require 'webmock/rspec'

describe Ronin::Vulns::CommandInjection do
  describe ".vuln_type" do
    subject { described_class }

    it "must return :command_injection" do
      expect(subject.vuln_type).to eq(:command_injection)
    end
  end

  describe "#initialize" do
    include_examples "Ronin::Vulns::WebVuln#initialize examples"

    it "must default #escape_quote to nil" do
      expect(subject.escape_quote).to be(nil)
    end

    it "must default #escape_operator to nil" do
      expect(subject.escape_operator).to be(nil)
    end

    it "must default #terminator to nil" do
      expect(subject.terminator).to be(nil)
    end

    context "when given the escape_quote: keyword is given" do
      let(:escape_quote) { '"' }

      subject do
        described_class.new(url, query_param:  query_param,
                                 escape_quote: escape_quote)
      end

      it "must set #escape_quote to the given String" do
        expect(subject.escape_quote).to eq(escape_quote)
      end
    end

    context "when given the escape_operator: keyword is given" do
      let(:escape_operator) { ';' }

      subject do
        described_class.new(url, query_param:     query_param,
                                 escape_operator: escape_operator)
      end

      it "must set #escape_operator to the given String" do
        expect(subject.escape_operator).to eq(escape_operator)
      end
    end

    context "when given the terminator: keyword is given" do
      let(:terminator) { '#' }

      subject do
        described_class.new(url, query_param: query_param,
                                 terminator:  terminator)
      end

      it "must set #terminator to the given String" do
        expect(subject.terminator).to eq(terminator)
      end
    end
  end

  describe ".test_param" do
    subject { described_class }

    let(:url)         { URI("https://example.com/page?foo=1&bar=2&baz=3") }
    let(:query_param) { 'bar' }
    let(:http)        { Ronin::Support::Network::HTTP.connect_uri(url) }

    let(:quotes)      { [nil, "'", '"', '`'] }
    let(:operators)   { [';', '|', '&', "\n"] }
    let(:terminators) { [nil, ';', '#', "\n"] }

    let(:uri_escaped_quotes) do
      quotes.map(&URI::QueryParams.method(:escape))
    end
    let(:uri_escaped_operators) do
      operators.map(&URI::QueryParams.method(:escape))
    end
    let(:uri_escaped_terminators) do
      terminators.map(&URI::QueryParams.method(:escape))
    end

    it "must test the URL and the specific param using every combination of escape quote characters, escape operator characters, and terminator characters, with the `id` and `sleep` commands" do
      uri_escaped_quotes.each do |quote|
        uri_escaped_operators.each do |operator|
          uri_escaped_terminators.each do |terminator|
            stub_request(:get,"https://example.com/page?bar=2#{quote}#{operator}id#{terminator}&baz=3&foo=1")
            stub_request(:get,"https://example.com/page?bar=2#{quote}#{operator}sleep 5#{terminator}&baz=3&foo=1")
          end
        end
      end

      subject.test_param(url, query_param: query_param, http: http)

      uri_escaped_quotes.each do |quote|
        uri_escaped_operators.each do |operator|
          uri_escaped_terminators.each do |terminator|
            expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2#{quote}#{operator}id#{terminator}&baz=3&foo=1")
            expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2#{quote}#{operator}sleep 5#{terminator}&baz=3&foo=1")
          end
        end
      end
    end

    context "and when one of the responses indicates a Command Injection vulnerability" do
      let(:vulnerable_response_body) do
        <<~HTML
          <html>
            <body>
              <p>example content</p>
              <p>command output here
          uid=1000(bob) gid=1000(bob) groups=1000(bob),63(audio),972(docker),985(pipewire) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023</p>
            </body>
          </html>
        HTML
      end

      it "must stop enumerating the combinations of escape quote characters, escape operator characters, and terminator characters and return a vulnerable #{described_class} object" do
        stub_request(:get,"https://example.com/page?bar=2#{uri_escaped_quotes[0]}#{uri_escaped_operators[0]}id#{uri_escaped_terminators[0]}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar=2#{uri_escaped_quotes[0]}#{uri_escaped_operators[0]}sleep 5#{uri_escaped_terminators[0]}&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?bar=2#{uri_escaped_quotes[0]}#{uri_escaped_operators[0]}id#{uri_escaped_terminators[1]}&baz=3&foo=1").to_return(status: 200, body: vulnerable_response_body)

        vuln = subject.test_param(url, query_param: query_param,
                                       http:        http)

        expect(vuln).to be_kind_of(described_class)
        expect(vuln.query_param).to eq(query_param)
        expect(vuln.escape_quote).to eq(quotes[0])
        expect(vuln.escape_operator).to eq(operators[0])
        expect(vuln.terminator).to eq(terminators[1])
      end
    end

    context "but none of the responses indicate a Command Injection vulnerability" do
      it "must return nil" do
        uri_escaped_quotes.each do |quote|
          uri_escaped_operators.each do |operator|
            uri_escaped_terminators.each do |terminator|
              stub_request(:get,"https://example.com/page?bar=2#{quote}#{operator}id#{terminator}&baz=3&foo=1")
              stub_request(:get,"https://example.com/page?bar=2#{quote}#{operator}sleep 5#{terminator}&baz=3&foo=1")
            end
          end
        end

        vuln = subject.test_param(url, query_param: query_param, http: http)

        expect(vuln).to be(nil)
      end
    end

    context "when given the escape_quote: keyword argument" do
      context "and it's a String" do
        let(:escape_quote)  { "'" }
        let(:quotes)        { [escape_quote] }

        it "must only use that escape quote character" do
          uri_escaped_quotes.each do |quote|
            uri_escaped_operators.each do |operator|
              uri_escaped_terminators.each do |terminator|
                stub_request(:get,"https://example.com/page?bar=2#{quote}#{operator}id#{terminator}&baz=3&foo=1")
                stub_request(:get,"https://example.com/page?bar=2#{quote}#{operator}sleep 5#{terminator}&baz=3&foo=1")
              end
            end
          end

          subject.test_param(url, query_param:  query_param,
                                  escape_quote: escape_quote,
                                  http:         http)

          uri_escaped_quotes.each do |quote|
            uri_escaped_operators.each do |operator|
              uri_escaped_terminators.each do |terminator|
                expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2#{quote}#{operator}id#{terminator}&baz=3&foo=1")
                expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2#{quote}#{operator}sleep 5#{terminator}&baz=3&foo=1")
              end
            end
          end
        end
      end

      context "and it's an Array" do
        let(:escape_quotes) { ["'", '`'] }
        let(:quotes)        { escape_quotes }

        it "must only test those escape quote characters" do
          uri_escaped_quotes.each do |quote|
            uri_escaped_operators.each do |operator|
              uri_escaped_terminators.each do |terminator|
                stub_request(:get,"https://example.com/page?bar=2#{quote}#{operator}id#{terminator}&baz=3&foo=1")
                stub_request(:get,"https://example.com/page?bar=2#{quote}#{operator}sleep 5#{terminator}&baz=3&foo=1")
              end
            end
          end

          subject.test_param(url, query_param:  query_param,
                                  escape_quote: escape_quotes,
                                  http:         http)

          uri_escaped_quotes.each do |quote|
            uri_escaped_operators.each do |operator|
              uri_escaped_terminators.each do |terminator|
                expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2#{quote}#{operator}id#{terminator}&baz=3&foo=1")
                expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2#{quote}#{operator}sleep 5#{terminator}&baz=3&foo=1")
              end
            end
          end
        end
      end
    end

    context "when given the escape_operator: keyword argument" do
      context "and it's a String" do
        let(:escape_operator)  { ";" }
        let(:operators)        { [escape_operator] }

        it "must only use that escape operator character" do
          uri_escaped_quotes.each do |quote|
            uri_escaped_operators.each do |operator|
              uri_escaped_terminators.each do |terminator|
                stub_request(:get,"https://example.com/page?bar=2#{quote}#{operator}id#{terminator}&baz=3&foo=1")
                stub_request(:get,"https://example.com/page?bar=2#{quote}#{operator}sleep 5#{terminator}&baz=3&foo=1")
              end
            end
          end

          subject.test_param(url, query_param:     query_param,
                                  escape_operator: escape_operator,
                                  http:            http)

          uri_escaped_quotes.each do |quote|
            uri_escaped_operators.each do |operator|
              uri_escaped_terminators.each do |terminator|
                expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2#{quote}#{operator}id#{terminator}&baz=3&foo=1")
                expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2#{quote}#{operator}sleep 5#{terminator}&baz=3&foo=1")
              end
            end
          end
        end
      end

      context "and it's an Array" do
        let(:escape_operators) { [";", '&'] }
        let(:operators)        { escape_operators }

        it "must only test those escape operators characters" do
          uri_escaped_quotes.each do |quote|
            uri_escaped_operators.each do |operator|
              uri_escaped_terminators.each do |terminator|
                stub_request(:get,"https://example.com/page?bar=2#{quote}#{operator}id#{terminator}&baz=3&foo=1")
                stub_request(:get,"https://example.com/page?bar=2#{quote}#{operator}sleep 5#{terminator}&baz=3&foo=1")
              end
            end
          end

          subject.test_param(url, query_param:     query_param,
                                  escape_operator: escape_operators,
                                  http:            http)

          uri_escaped_quotes.each do |quote|
            uri_escaped_operators.each do |operator|
              uri_escaped_terminators.each do |terminator|
                expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2#{quote}#{operator}id#{terminator}&baz=3&foo=1")
                expect(WebMock).to have_requested(:get,"https://example.com/page?bar=2#{quote}#{operator}sleep 5#{terminator}&baz=3&foo=1")
              end
            end
          end
        end
      end
    end
  end

  let(:query_param)     { 'bar' }
  let(:original_value)  { '2' }
  let(:escape_quote)    { "'" }
  let(:escape_operator) { ';' }

  let(:url) do
    "https://example.com/page?foo=1&#{query_param}=#{original_value}&baz=3"
  end

  subject do
    described_class.new(url, query_param:     query_param,
                             escape_quote:    escape_quote,
                             escape_operator: escape_operator)
  end

  describe "#escape" do
    let(:command) { 'ls' }

    let(:escape_quote)    { nil }
    let(:escape_operator) { nil }
    let(:terminator)      { nil }

    subject do
      described_class.new(url, query_param:     query_param,
                               escape_quote:    escape_quote,
                               escape_operator: escape_operator,
                               terminator:      terminator)
    end

    context "when #escape_quote is nil" do
      context "and when #escape_operator is nil" do
        it "must return the unescaped command" do
          expect(subject.escape(command)).to eq(command)
        end

        context "and when #terminator is ';'" do
          let(:terminator) { ';' }

          it "must append a ';' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{command};")
          end
        end

        context "and when #terminator is '#'" do
          let(:terminator) { '#' }

          it "must append a '#' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{command}#")
          end
        end

        context "and when #terminator is '\\n'" do
          let(:terminator) { "\n" }

          it "must append a '\\n' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{command}\n")
          end
        end
      end

      context "and when #escape_operator is ';'" do
        let(:escape_operator) { ';' }

        it "must return the \"\#{original_value};...\"" do
          expect(subject.escape(command)).to eq("#{subject.original_value};#{command}")
        end

        context "and when #terminator is ';'" do
          let(:terminator) { ';' }

          it "must append a ';' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value};#{command};")
          end
        end

        context "and when #terminator is '#'" do
          let(:terminator) { '#' }

          it "must append a '#' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value};#{command}#")
          end
        end

        context "and when #terminator is '\\n'" do
          let(:terminator) { "\n" }

          it "must append a '\\n' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value};#{command}\n")
          end
        end
      end

      context "when #escape_operator is '|'" do
        let(:escape_operator) { '|' }

        it "must return the \"\#{original_value}|...\"" do
          expect(subject.escape(command)).to eq("#{subject.original_value}|#{command}")
        end

        context "and when #terminator is ';'" do
          let(:terminator) { ';' }

          it "must append a ';' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}|#{command};")
          end
        end

        context "and when #terminator is '#'" do
          let(:terminator) { '#' }

          it "must append a '#' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}|#{command}#")
          end
        end

        context "and when #terminator is '\\n'" do
          let(:terminator) { "\n" }

          it "must append a '\\n' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}|#{command}\n")
          end
        end
      end

      context "when #escape_operator is '&'" do
        let(:escape_operator) { '&' }

        it "must return the \"\#{original_value}&...\"" do
          expect(subject.escape(command)).to eq("#{subject.original_value}&#{command}")
        end

        context "and when #terminator is ';'" do
          let(:terminator) { ';' }

          it "must append a ';' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}&#{command};")
          end
        end

        context "and when #terminator is '#'" do
          let(:terminator) { '#' }

          it "must append a '#' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}&#{command}#")
          end
        end

        context "and when #terminator is '\\n'" do
          let(:terminator) { "\n" }

          it "must append a '\\n' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}&#{command}\n")
          end
        end
      end

      context "when #escape_operator is '\\n'" do
        let(:escape_operator) { "\n" }

        it "must return the \"\#{original_value}\\n...\"" do
          expect(subject.escape(command)).to eq("#{subject.original_value}\n#{command}")
        end

        context "and when #terminator is ';'" do
          let(:terminator) { ';' }

          it "must append a ';' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}\n#{command};")
          end
        end

        context "and when #terminator is '#'" do
          let(:terminator) { '#' }

          it "must append a '#' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}\n#{command}#")
          end
        end

        context "and when #terminator is '\\n'" do
          let(:terminator) { "\n" }

          it "must append a '\\n' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}\n#{command}\n")
          end
        end
      end
    end

    context "and when #escape_quote is \"'\"" do
      let(:escape_quote) { "'" }

      context "when #escape_operator is ';'" do
        let(:escape_operator) { ';' }

        it "must return the \"\#{original_value}';...\"" do
          expect(subject.escape(command)).to eq("#{subject.original_value}';#{command}")
        end

        context "but the command ends with a \"'\" character" do
          let(:command) { "ls 'foo'" }

          it "must remove the ending \"'\" character" do
            expect(subject.escape(command)).to eq("#{subject.original_value}';#{command[0..-2]}")
          end
        end

        context "and when #terminator is ';'" do
          let(:terminator) { ';' }

          it "must append a ';' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}';#{command};")
          end
        end

        context "and when #terminator is '#'" do
          let(:terminator) { '#' }

          it "must append a '#' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}';#{command}#")
          end
        end

        context "and when #terminator is '\\n'" do
          let(:terminator) { "\n" }

          it "must append a '\\n' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}';#{command}\n")
          end
        end
      end

      context "when #escape_operator is '|'" do
        let(:escape_operator) { '|' }

        it "must return the \"\#{original_value}'|...\"" do
          expect(subject.escape(command)).to eq("#{subject.original_value}'|#{command}")
        end

        context "but the command ends with a \"'\" character" do
          let(:command) { "ls 'foo'" }

          it "must remove the ending \"'\" character" do
            expect(subject.escape(command)).to eq("#{subject.original_value}'|#{command[0..-2]}")
          end
        end

        context "and when #terminator is ';'" do
          let(:terminator) { ';' }

          it "must append a ';' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}'|#{command};")
          end
        end

        context "and when #terminator is '#'" do
          let(:terminator) { '#' }

          it "must append a '#' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}'|#{command}#")
          end
        end

        context "and when #terminator is '\\n'" do
          let(:terminator) { "\n" }

          it "must append a '\\n' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}'|#{command}\n")
          end
        end
      end

      context "when #escape_operator is '&'" do
        let(:escape_operator) { '&' }

        it "must return the \"\#{original_value}'&...\"" do
          expect(subject.escape(command)).to eq("#{subject.original_value}'&#{command}")
        end

        context "but the command ends with a \"'\" character" do
          let(:command) { "ls 'foo'" }

          it "must remove the ending \"'\" character" do
            expect(subject.escape(command)).to eq("#{subject.original_value}'&#{command[0..-2]}")
          end
        end

        context "and when #terminator is ';'" do
          let(:terminator) { ';' }

          it "must append a ';' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}'&#{command};")
          end
        end

        context "and when #terminator is '#'" do
          let(:terminator) { '#' }

          it "must append a '#' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}'&#{command}#")
          end
        end

        context "and when #terminator is '\\n'" do
          let(:terminator) { "\n" }

          it "must append a '\\n' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}'&#{command}\n")
          end
        end
      end

      context "when #escape_operator is '\\n'" do
        let(:escape_operator) { "\n" }

        it "must return the \"\#{original_value}'\\n...\"" do
          expect(subject.escape(command)).to eq("#{subject.original_value}'\n#{command}")
        end

        context "but the command ends with a \"'\" character" do
          let(:command) { "ls 'foo'" }

          it "must remove the ending \"'\" character" do
            expect(subject.escape(command)).to eq("#{subject.original_value}'\n#{command[0..-2]}")
          end
        end

        context "and when #terminator is ';'" do
          let(:terminator) { ';' }

          it "must append a ';' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}'\n#{command};")
          end
        end

        context "and when #terminator is '#'" do
          let(:terminator) { '#' }

          it "must append a '#' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}'\n#{command}#")
          end
        end

        context "and when #terminator is '\\n'" do
          let(:terminator) { "\n" }

          it "must append a '\\n' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}'\n#{command}\n")
          end
        end
      end
    end

    context "and when #escape_quote is '\"'" do
      let(:escape_quote) { '"' }

      context "when #escape_operator is ';'" do
        let(:escape_operator) { ';' }

        it "must return the '\#{original_value}\";...'" do
          expect(subject.escape(command)).to eq("#{subject.original_value}\";#{command}")
        end

        context "but the command ends with a '\"' character" do
          let(:command) { 'ls "foo"' }

          it "must remove the ending '\"' character" do
            expect(subject.escape(command)).to eq("#{subject.original_value}\";#{command[0..-2]}")
          end
        end

        context "and when #terminator is ';'" do
          let(:terminator) { ';' }

          it "must append a ';' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}\";#{command};")
          end
        end

        context "and when #terminator is '#'" do
          let(:terminator) { '#' }

          it "must append a '#' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}\";#{command}#")
          end
        end

        context "and when #terminator is '\\n'" do
          let(:terminator) { "\n" }

          it "must append a '\\n' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}\";#{command}\n")
          end
        end
      end

      context "when #escape_operator is '|'" do
        let(:escape_operator) { '|' }

        it "must return the '\#{original_value}\"|...'" do
          expect(subject.escape(command)).to eq("#{subject.original_value}\"|#{command}")
        end

        context "but the command ends with a '\"' character" do
          let(:command) { 'ls "foo"' }

          it "must remove the ending '\"' character" do
            expect(subject.escape(command)).to eq("#{subject.original_value}\"|#{command[0..-2]}")
          end
        end

        context "and when #terminator is ';'" do
          let(:terminator) { ';' }

          it "must append a ';' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}\"|#{command};")
          end
        end

        context "and when #terminator is '#'" do
          let(:terminator) { '#' }

          it "must append a '#' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}\"|#{command}#")
          end
        end

        context "and when #terminator is '\\n'" do
          let(:terminator) { "\n" }

          it "must append a '\\n' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}\"|#{command}\n")
          end
        end
      end

      context "when #escape_operator is '&'" do
        let(:escape_operator) { '&' }

        it "must return the '\#{original_value}\"&...'" do
          expect(subject.escape(command)).to eq("#{subject.original_value}\"&#{command}")
        end

        context "but the command ends with a '\"' character" do
          let(:command) { 'ls "foo"' }

          it "must remove the ending '\"' character" do
            expect(subject.escape(command)).to eq("#{subject.original_value}\"&#{command[0..-2]}")
          end
        end

        context "and when #terminator is ';'" do
          let(:terminator) { ';' }

          it "must append a ';' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}\"&#{command};")
          end
        end

        context "and when #terminator is '#'" do
          let(:terminator) { '#' }

          it "must append a '#' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}\"&#{command}#")
          end
        end

        context "and when #terminator is '\\n'" do
          let(:terminator) { "\n" }

          it "must append a '\\n' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}\"&#{command}\n")
          end
        end
      end

      context "when #escape_operator is '\\n'" do
        let(:escape_operator) { "\n" }

        it "must return the '\#{original_value}\"\\n...'" do
          expect(subject.escape(command)).to eq("#{subject.original_value}\"\n#{command}")
        end

        context "but the command ends with a '\"' character" do
          let(:command) { 'ls "foo"' }

          it "must remove the ending '\"' character" do
            expect(subject.escape(command)).to eq("#{subject.original_value}\"\n#{command[0..-2]}")
          end
        end

        context "and when #terminator is ';'" do
          let(:terminator) { ';' }

          it "must append a ';' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}\"\n#{command};")
          end
        end

        context "and when #terminator is '#'" do
          let(:terminator) { '#' }

          it "must append a '#' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}\"\n#{command}#")
          end
        end

        context "and when #terminator is '\\n'" do
          let(:terminator) { "\n" }

          it "must append a '\\n' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}\"\n#{command}\n")
          end
        end
      end
    end

    context "and when #escape_quote is '`'" do
      let(:escape_quote) { '`' }

      context "when #escape_operator is ';'" do
        let(:escape_operator) { ';' }

        it "must return the \"\#{original_value}`;...\"" do
          expect(subject.escape(command)).to eq("#{subject.original_value}`;#{command}")
        end

        context "but the command ends with a '`' character" do
          let(:command) { 'ls `foo`' }

          it "must remove the ending '`' character" do
            expect(subject.escape(command)).to eq("#{subject.original_value}`;#{command[0..-2]}")
          end
        end

        context "and when #terminator is ';'" do
          let(:terminator) { ';' }

          it "must append a ';' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}`;#{command};")
          end
        end

        context "and when #terminator is '#'" do
          let(:terminator) { '#' }

          it "must append a '#' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}`;#{command}#")
          end
        end

        context "and when #terminator is '\\n'" do
          let(:terminator) { "\n" }

          it "must append a '\\n' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}`;#{command}\n")
          end
        end
      end

      context "when #escape_operator is '|'" do
        let(:escape_operator) { '|' }

        it "must return the \"\#{original_value}`|...\"" do
          expect(subject.escape(command)).to eq("#{subject.original_value}`|#{command}")
        end

        context "but the command ends with a '`' character" do
          let(:command) { 'ls `foo`' }

          it "must remove the ending '`' character" do
            expect(subject.escape(command)).to eq("#{subject.original_value}`|#{command[0..-2]}")
          end
        end

        context "and when #terminator is ';'" do
          let(:terminator) { ';' }

          it "must append a ';' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}`|#{command};")
          end
        end

        context "and when #terminator is '#'" do
          let(:terminator) { '#' }

          it "must append a '#' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}`|#{command}#")
          end
        end

        context "and when #terminator is '\\n'" do
          let(:terminator) { "\n" }

          it "must append a '\\n' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}`|#{command}\n")
          end
        end
      end

      context "when #escape_operator is '&'" do
        let(:escape_operator) { '&' }

        it "must return the \"\#{original_value}`&...\"" do
          expect(subject.escape(command)).to eq("#{subject.original_value}`&#{command}")
        end

        context "but the command ends with a '`' character" do
          let(:command) { 'ls `foo`' }

          it "must remove the ending '`' character" do
            expect(subject.escape(command)).to eq("#{subject.original_value}`&#{command[0..-2]}")
          end
        end

        context "and when #terminator is ';'" do
          let(:terminator) { ';' }

          it "must append a ';' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}`&#{command};")
          end
        end

        context "and when #terminator is '#'" do
          let(:terminator) { '#' }

          it "must append a '#' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}`&#{command}#")
          end
        end

        context "and when #terminator is '\\n'" do
          let(:terminator) { "\n" }

          it "must append a '\\n' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}`&#{command}\n")
          end
        end
      end

      context "when #escape_operator is '\\n'" do
        let(:escape_operator) { "\n" }

        it "must return the \"\#{original_value}`\\n...\"" do
          expect(subject.escape(command)).to eq("#{subject.original_value}`\n#{command}")
        end

        context "but the command ends with a '`' character" do
          let(:command) { 'ls `foo`' }

          it "must remove the ending '`' character" do
            expect(subject.escape(command)).to eq("#{subject.original_value}`\n#{command[0..-2]}")
          end
        end

        context "and when #terminator is ';'" do
          let(:terminator) { ';' }

          it "must append a ';' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}`\n#{command};")
          end
        end

        context "and when #terminator is '#'" do
          let(:terminator) { '#' }

          it "must append a '#' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}`\n#{command}#")
          end
        end

        context "and when #terminator is '\\n'" do
          let(:terminator) { "\n" }

          it "must append a '\\n' to the end of the escaped command string" do
            expect(subject.escape(command)).to eq("#{subject.original_value}`\n#{command}\n")
          end
        end
      end
    end
  end

  describe "#encode_payload" do
    let(:command) { 'ls' }

    it "must call #escape with the command string" do
      expect(subject.encode_payload(command)).to eq(subject.escape(command))
    end
  end

  let(:normal_response_body) do
    <<~HTML
      <html>
        <body>
          <p>example content</p>
          <p>command output here</p>
        </body>
      </html>
    HTML
  end

  describe "#test_command_output" do
    it "must send a request containing 'id'" do
      stub_request(:get,"https://example.com/page?#{query_param}=#{original_value}';id&baz=3&foo=1")

      subject.test_command_output
    end

    context "when the response contains the output of the `id` command" do
      let(:response_body) do
        <<~HTML
          <html>
            <body>
              <p>example content</p>
              <p>command output here
          uid=1000(bob) gid=1000(bob) groups=1000(bob),63(audio),972(docker),985(pipewire) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023</p>
            </body>
          </html>
        HTML
      end

      it "must return true" do
        stub_request(:get,"https://example.com/page?#{query_param}=#{original_value}';id&baz=3&foo=1").to_return(status: 200, body: response_body)

        expect(subject.test_command_output).to be(true)
      end
    end

    context "when the response does not contain the output of the `id` command" do
      it "must return false" do
        stub_request(:get,"https://example.com/page?#{query_param}=#{original_value}';id&baz=3&foo=1").to_return(status: 200, body: normal_response_body)

        expect(subject.test_command_output).to be_falsy
      end
    end
  end

  describe "#test_sleep" do
    it "must send a \"sleep 5\" command" do
      stub_request(:get,"https://example.com/page?#{query_param}=#{original_value}';sleep 5&baz=3&foo=1")

      subject.test_sleep
    end

    context "when none of the responses take at most 5 seconds to complete" do
      it "must return false" do
        time = Time.now

        allow(Time).to receive(:now).and_return(
          time,
          time + 2 # 2 second later
        )

        stub_request(:get,"https://example.com/page?#{query_param}=#{original_value}';sleep 5&baz=3&foo=1").to_return(status: 200, body: normal_response_body)

        expect(subject.test_sleep).to be(false)
      end
    end

    context "when one of the responses takes more than 5 seconds to complete" do
      it "must return true" do
        time = Time.now

        allow(Time).to receive(:now).and_return(
          time,
          time + 5.5 # 5.5  second later
        )

        stub_request(:get,"https://example.com/page?#{query_param}=#{original_value}';sleep 5&baz=3&foo=1").to_return(status: 200, body: normal_response_body)

        expect(subject.test_sleep).to be(true)
      end
    end
  end

  describe "#vulnerable?" do
    it "must call #test_command_output then #test_sleep" do
      expect(subject).to receive(:test_command_output)
      expect(subject).to receive(:test_sleep)

      subject.vulnerable?
    end

    context "when #test_command_output returns true" do
      it "must return true" do
        expect(subject).to receive(:test_command_output).and_return(true)

        expect(subject.vulnerable?).to be(true)
      end

      it "must not call #test_sleep" do
        expect(subject).to receive(:test_command_output).and_return(true)
        expect(subject).to_not receive(:test_sleep)

        expect(subject.vulnerable?).to be(true)
      end
    end

    context "when #test_command_output returns false" do
      it "must call #test_sleep next" do
        expect(subject).to receive(:test_command_output).and_return(false)
        expect(subject).to receive(:test_sleep)

        subject.vulnerable?
      end

      context "and when #test_sleep returns true" do
        it "must return true" do
          expect(subject).to receive(:test_command_output).and_return(false)
          expect(subject).to receive(:test_sleep).and_return(true)

          expect(subject.vulnerable?).to be(true)
        end
      end

      context "and when #test_sleep returns false" do
        it "must return false" do
          expect(subject).to receive(:test_command_output).and_return(false)
          expect(subject).to receive(:test_sleep).and_return(false)

          expect(subject.vulnerable?).to be(false)
        end
      end
    end
  end
end
