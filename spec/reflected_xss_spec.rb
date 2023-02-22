require 'spec_helper'
require 'web_vuln_examples'
require 'ronin/vulns/reflected_xss'

require 'webmock/rspec'

describe Ronin::Vulns::ReflectedXSS do
  describe ".vuln_type" do
    subject { described_class }

    it "must return :reflected_xss" do
      expect(subject.vuln_type).to eq(:reflected_xss)
    end
  end

  describe "#initialize" do
    include_examples "Ronin::Vulns::WebVuln#initialize examples"
  end

  let(:query_param) { 'bar' }
  let(:url)         { "https://example.com/page?foo=1&bar=2&baz=3" }

  subject { described_class.new(url, query_param: query_param) }

  describe "#test_string" do
    let(:random_value1) { 'ABC' }
    let(:random_value2) { 'XYZ' }

    before do
      allow(subject).to receive(:random_value).and_return(
        random_value1,
        random_value2
      )
    end

    let(:test_string) do
      described_class::TestString.new(
        %{'"= /><&},
        %r{(?:(')|&#39;)?(?:(")|&quote;)?(=)?(?:( )|&nbsp;)?(/)?(?:(>)|&gt;)?(?:(<)|&lt;)?(?:(&)|&amp;)?}
      )
    end

    let(:content_type) { 'text/html; charset=UTF-8' }
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
    let(:response) do
      double('Net::HTTPResponse', content_type: content_type,
                                  body:         response_body)
    end

    before do
      expect(subject).to receive(:exploit).with("#{subject.original_value}#{random_value1}#{test_string}#{random_value2}").and_return(response)
    end

    it "must call #exploit with the original param value and the test_string with a random prefix and suffix" do
      subject.test_string(test_string)
    end

    context "but the 'Content-Type' is nil" do
      let(:content_type) { nil }

      it "must not yield anything" do
        expect { |b|
          subject.test_string(test_string,&b)
        }.to_not yield_control
      end
    end

    context "and the 'Content-Type' includes 'text/html'" do
      let(:content_type) { 'text/html; charset=UTF-8' }

      context "and the response body matches the test_string" do
        let(:response_body) do
          <<~HTML
          <html>
            <body>
              <p>example content</p>
              <p>#{random_value1}#{test_string}#{random_value2}</p>
              <p>more content</p>
            </body>
          </html>
          HTML
        end

        let(:wrapped_test_string) do
          test_string.wrap(random_value1,random_value2)
        end
        let(:match_data) do
          wrapped_test_string.match(response_body)
        end

        it "must yield the body and the match data" do
          yielded_body  = nil
          yielded_match = nil

          subject.test_string(test_string) do |body,match|
            yielded_body  = body
            yielded_match = match
          end

          expect(yielded_body).to eq(response_body)
          expect(yielded_match).to be_kind_of(MatchData)
          expect(yielded_match[0]).to eq("#{random_value1}#{test_string}#{random_value2}")
          expect(yielded_match[1]).to eq("'")
          expect(yielded_match[2]).to eq('"')
          expect(yielded_match[3]).to eq('=')
          expect(yielded_match[4]).to eq(' ')
          expect(yielded_match[5]).to eq('/')
          expect(yielded_match[6]).to eq('>')
          expect(yielded_match[7]).to eq('<')
          expect(yielded_match[8]).to eq('&')
        end
      end

      context "but some of the characters in the test string were HTML escaped" do
        let(:response_body) do
          <<~HTML
          <html>
            <body>
              <p>example content</p>
              <p>#{random_value1}'"= /&gt;&lt;&amp;#{random_value2}</p>
              <p>more content</p>
            </body>
          </html>
          HTML
        end

        it "must yield the matched characters and ignore the escaped ones" do
          yielded_body  = nil
          yielded_match = nil

          subject.test_string(test_string) do |body,match|
            yielded_body  = body
            yielded_match = match
          end

          expect(yielded_match[1]).to eq("'")
          expect(yielded_match[2]).to eq('"')
          expect(yielded_match[3]).to eq('=')
          expect(yielded_match[4]).to eq(' ')
          expect(yielded_match[5]).to eq('/')
          expect(yielded_match[6]).to be(nil)
          expect(yielded_match[7]).to be(nil)
          expect(yielded_match[8]).to be(nil)
        end
      end

      context "but some of the characters in the test string were filtered out" do
        let(:response_body) do
          <<~HTML
          <html>
            <body>
              <p>example content</p>
              <p>#{random_value1}'"= /#{random_value2}</p>
              <p>more content</p>
            </body>
          </html>
          HTML
        end

        it "must yield the matched characters and ignore the filtered ones" do
          yielded_body  = nil
          yielded_match = nil

          subject.test_string(test_string) do |body,match|
            yielded_body  = body
            yielded_match = match
          end

          expect(yielded_match[1]).to eq("'")
          expect(yielded_match[2]).to eq('"')
          expect(yielded_match[3]).to eq('=')
          expect(yielded_match[4]).to eq(' ')
          expect(yielded_match[5]).to eq('/')
          expect(yielded_match[6]).to be(nil)
          expect(yielded_match[7]).to be(nil)
          expect(yielded_match[8]).to be(nil)
        end
      end

      context "and the response body does not match the test_string" do
        it "must not yield anything" do
          expect { |b|
            subject.test_string(test_string,&b)
          }.to_not yield_control
        end
      end
    end

    context "and the 'Content-Type' does not include 'text/html'" do
      let(:content_type) { 'text/xml' }

      it "must not yield anything" do
        expect { |b|
          subject.test_string(test_string,&b)
        }.to_not yield_control
      end
    end
  end

  describe "#test_chars" do
    let(:random_value1) { 'ABC' }
    let(:random_value2) { 'XYZ' }

    before do
      allow(subject).to receive(:random_value).and_return(
        random_value1,
        random_value2
      )
    end

    let(:test_string) do
      described_class::TestString.new(
        %{'"= /><&},
        %r{(?:(')|&#39;)?(?:(")|&quote;)?(=)?(?:( )|&nbsp;)?(/)?(?:(>)|&gt;)?(?:(<)|&lt;)?(?:(&)|&amp;)?}
      )
    end

    let(:content_type) { 'text/html; charset=UTF-8' }
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
    let(:response) do
      double('Net::HTTPResponse', content_type: content_type,
                                  body:         response_body)
    end

    before do
      expect(subject).to receive(:exploit).with("#{subject.original_value}#{random_value1}#{test_string}#{random_value2}").and_return(response)
    end

    it "must call #exploit with the original param value and the test_string with a random prefix and suffix" do
      subject.test_chars(test_string)
    end

    context "but the 'Content-Type' is nil" do
      let(:content_type) { nil }

      it "must not yield anything" do
        expect { |b|
          subject.test_chars(test_string,&b)
        }.to_not yield_control
      end

      it "must not set #allowed_chars" do
        subject.test_chars(test_string)

        expect(subject.allowed_chars).to be(nil)
      end
    end

    context "and the 'Content-Type' includes 'text/html'" do
      let(:content_type) { 'text/html; charset=UTF-8' }

      context "and the response body matches the test_string" do
        let(:response_body) do
          <<~HTML
          <html>
            <body>
              <p>example content</p>
              <p>#{random_value1}#{test_string}#{random_value2}</p>
              <p>more content</p>
            </body>
          </html>
          HTML
        end

        let(:wrapped_test_string) do
          test_string.wrap(random_value1,random_value2)
        end
        let(:match_data) do
          wrapped_test_string.match(response_body)
        end

        it "must yield the body and the match data" do
          yielded_body  = nil
          yielded_match = nil

          subject.test_chars(test_string) do |body,match|
            yielded_body  = body
            yielded_match = match
          end

          expect(yielded_body).to eq(response_body)
          expect(yielded_match).to be_kind_of(MatchData)
          expect(yielded_match[0]).to eq("#{random_value1}#{test_string}#{random_value2}")
          expect(yielded_match[1]).to eq("'")
          expect(yielded_match[2]).to eq('"')
          expect(yielded_match[3]).to eq('=')
          expect(yielded_match[4]).to eq(' ')
          expect(yielded_match[5]).to eq('/')
          expect(yielded_match[6]).to eq('>')
          expect(yielded_match[7]).to eq('<')
          expect(yielded_match[8]).to eq('&')
        end

        it "must populate #allowed_chars with the unescaped characters" do
          subject.test_chars(test_string) do |body,match|
          end

          expect(subject.allowed_chars).to be_kind_of(Set)
          expect(subject.allowed_chars.to_a).to eq(
            ["'", '"', '=', ' ', '/', '>', '<', '&']
          )
        end
      end

      context "but some of the characters in the test string were HTML escaped" do
        let(:response_body) do
          <<~HTML
          <html>
            <body>
              <p>example content</p>
              <p>#{random_value1}'"= /&gt;&lt;&amp;#{random_value2}</p>
              <p>more content</p>
            </body>
          </html>
          HTML
        end

        it "must match characters and ignore the escaped ones" do
          yielded_body  = nil
          yielded_match = nil

          subject.test_chars(test_string) do |body,match|
            yielded_body  = body
            yielded_match = match
          end

          expect(yielded_match[1]).to eq("'")
          expect(yielded_match[2]).to eq('"')
          expect(yielded_match[3]).to eq('=')
          expect(yielded_match[4]).to eq(' ')
          expect(yielded_match[5]).to eq('/')
          expect(yielded_match[6]).to be(nil)
          expect(yielded_match[7]).to be(nil)
          expect(yielded_match[8]).to be(nil)
        end

        it "must populate #allowed_chars with the unescaped characters" do
          subject.test_chars(test_string) do |body,match|
          end

          expect(subject.allowed_chars).to be_kind_of(Set)
          expect(subject.allowed_chars.to_a).to eq(["'", '"', '=', ' ', '/'])
        end
      end

      context "but some of the characters in the test string were filtered out" do
        let(:response_body) do
          <<~HTML
          <html>
            <body>
              <p>example content</p>
              <p>#{random_value1}'"= /#{random_value2}</p>
              <p>more content</p>
            </body>
          </html>
          HTML
        end

        it "must yield the matched characters and ignore the filtered ones" do
          yielded_body  = nil
          yielded_match = nil

          subject.test_chars(test_string) do |body,match|
            yielded_body  = body
            yielded_match = match
          end

          expect(yielded_match[1]).to eq("'")
          expect(yielded_match[2]).to eq('"')
          expect(yielded_match[3]).to eq('=')
          expect(yielded_match[4]).to eq(' ')
          expect(yielded_match[5]).to eq('/')
          expect(yielded_match[6]).to be(nil)
          expect(yielded_match[7]).to be(nil)
          expect(yielded_match[8]).to be(nil)
        end

        it "must populate #allowed_chars with the unescaped characters" do
          subject.test_chars(test_string) do |body,match|
          end

          expect(subject.allowed_chars).to be_kind_of(Set)
          expect(subject.allowed_chars.to_a).to eq(["'", '"', '=', ' ', '/'])
        end
      end

      context "and the response body does not match the test_string" do
        it "must not yield anything" do
          expect { |b|
            subject.test_chars(test_string,&b)
          }.to_not yield_control
        end

        it "must not set #allowed_chars" do
          subject.test_chars(test_string)

          expect(subject.allowed_chars).to be(nil)
        end
      end
    end

    context "and the 'Content-Type' does not include 'text/html'" do
      let(:content_type) { 'text/xml' }

      it "must not yield anything" do
        expect { |b|
          subject.test_chars(test_string,&b)
        }.to_not yield_control
      end

      it "must not set #allowed_chars" do
        subject.test_chars(test_string)

        expect(subject.allowed_chars).to be(nil)
      end
    end
  end

  describe "#test_html_chars" do
    let(:random_value1) { 'ABC' }
    let(:random_value2) { 'XYZ' }

    before do
      allow(subject).to receive(:random_value).and_return(
        random_value1,
        random_value2
      )
    end

    let(:test_string) { described_class::HTML_TEST_STRING }

    let(:content_type) { 'text/html; charset=UTF-8' }
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
    let(:response) do
      double('Net::HTTPResponse', content_type: content_type,
                                  body:         response_body)
    end

    before do
      expect(subject).to receive(:exploit).with("#{subject.original_value}#{random_value1}#{test_string}#{random_value2}").and_return(response)
    end

    it "must call #exploit with the original param value and the HTML test string with a random prefix and suffix" do
      subject.test_html_chars
    end

    context "but the 'Content-Type' is nil" do
      let(:content_type) { nil }

      it "must not yield anything" do
        expect { |b|
          subject.test_html_chars(&b)
        }.to_not yield_control
      end

      it "must not set #allowed_chars" do
        subject.test_html_chars

        expect(subject.allowed_chars).to be(nil)
      end
    end

    context "and the 'Content-Type' includes 'text/html'" do
      let(:content_type) { 'text/html; charset=UTF-8' }

      context "and the response body matches the test_string" do
        let(:response_body) do
          <<~HTML
          <html>
            <body>
              <p>example content</p>
              <p>#{random_value1}#{test_string}#{random_value2}</p>
              <p>more content</p>
            </body>
          </html>
          HTML
        end

        let(:wrapped_test_string) do
          test_string.wrap(random_value1,random_value2)
        end
        let(:match_data) do
          wrapped_test_string.match(response_body)
        end

        it "must yield the body and the match data" do
          yielded_body  = nil
          yielded_match = nil

          subject.test_html_chars do |body,match|
            yielded_body  = body
            yielded_match = match
          end

          expect(yielded_body).to eq(response_body)
          expect(yielded_match).to be_kind_of(MatchData)
          expect(yielded_match[0]).to eq("#{random_value1}#{test_string}#{random_value2}")
          expect(yielded_match[1]).to eq("'")
          expect(yielded_match[2]).to eq('"')
          expect(yielded_match[3]).to eq('=')
          expect(yielded_match[4]).to eq(' ')
          expect(yielded_match[5]).to eq('/')
          expect(yielded_match[6]).to eq('>')
          expect(yielded_match[7]).to eq('<')
        end

        it "must populate #allowed_chars with the unescaped characters" do
          subject.test_html_chars { |body,match| }

          expect(subject.allowed_chars).to be_kind_of(Set)
          expect(subject.allowed_chars.to_a).to eq(
            ["'", '"', '=', ' ', '/', '>', '<']
          )
        end
      end

      context "but some of the characters in the test string were HTML escaped" do
        let(:response_body) do
          <<~HTML
          <html>
            <body>
              <p>example content</p>
              <p>#{random_value1}'"= /&gt;&lt;#{random_value2}</p>
              <p>more content</p>
            </body>
          </html>
          HTML
        end

        it "must match characters and ignore the escaped ones" do
          yielded_body  = nil
          yielded_match = nil

          subject.test_html_chars do |body,match|
            yielded_body  = body
            yielded_match = match
          end

          expect(yielded_match[1]).to eq("'")
          expect(yielded_match[2]).to eq('"')
          expect(yielded_match[3]).to eq('=')
          expect(yielded_match[4]).to eq(' ')
          expect(yielded_match[5]).to eq('/')
          expect(yielded_match[6]).to be(nil)
          expect(yielded_match[7]).to be(nil)
        end

        it "must populate #allowed_chars with the unescaped characters" do
          subject.test_html_chars { |body,match| }

          expect(subject.allowed_chars).to be_kind_of(Set)
          expect(subject.allowed_chars.to_a).to eq(["'", '"', '=', ' ', '/'])
        end
      end

      context "but some of the characters in the test string were filtered out" do
        let(:response_body) do
          <<~HTML
          <html>
            <body>
              <p>example content</p>
              <p>#{random_value1}'"= /#{random_value2}</p>
              <p>more content</p>
            </body>
          </html>
          HTML
        end

        it "must yield the matched characters and ignore the filtered ones" do
          yielded_body  = nil
          yielded_match = nil

          subject.test_html_chars do |body,match|
            yielded_body  = body
            yielded_match = match
          end

          expect(yielded_match[1]).to eq("'")
          expect(yielded_match[2]).to eq('"')
          expect(yielded_match[3]).to eq('=')
          expect(yielded_match[4]).to eq(' ')
          expect(yielded_match[5]).to eq('/')
          expect(yielded_match[6]).to be(nil)
          expect(yielded_match[7]).to be(nil)
        end

        it "must populate #allowed_chars with the unescaped characters" do
          subject.test_html_chars { |body,match| }

          expect(subject.allowed_chars).to be_kind_of(Set)
          expect(subject.allowed_chars.to_a).to eq(["'", '"', '=', ' ', '/'])
        end
      end

      context "and the response body does not match the test_string" do
        it "must not yield anything" do
          expect { |b|
            subject.test_html_chars(&b)
          }.to_not yield_control
        end

        it "must not set #allowed_chars" do
          subject.test_html_chars

          expect(subject.allowed_chars).to be(nil)
        end
      end
    end

    context "and the 'Content-Type' does not include 'text/html'" do
      let(:content_type) { 'text/xml' }

      it "must not yield anything" do
        expect { |b|
          subject.test_html_chars(&b)
        }.to_not yield_control
      end

      it "must not set #allowed_chars" do
        subject.test_html_chars

        expect(subject.allowed_chars).to be(nil)
      end
    end
  end

  describe "#vulnerable?" do
    let(:original_value) { subject.original_value }
    let(:random_value1)  { 'ABC' }
    let(:random_value2)  { 'XYZ' }

    before do
      allow(subject).to receive(:random_value).and_return(
        random_value1,
        random_value2
      )
    end

    let(:test_string) { described_class::HTML_TEST_STRING }

    let(:content_type) { 'text/html; charset=UTF-8' }
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
    let(:response) do
      double('Net::HTTPResponse', content_type: content_type,
                                  body:         response_body)
    end

    before do
      expect(subject).to receive(:exploit).with("#{subject.original_value}#{random_value1}#{test_string}#{random_value2}").and_return(response)
    end

    it "must call #exploit with the original param value and the HTML test string with a random prefix and suffix" do
      subject.vulnerable?
    end

    context "but the 'Content-Type' is nil" do
      let(:content_type) { nil }

      it "must return false" do
        expect(subject.vulnerable?).to be(false)
      end

      it "must not set #allowed_chars" do
        subject.vulnerable?

        expect(subject.allowed_chars).to be(nil)
      end

      it "must not set #context" do
        subject.vulnerable?

        expect(subject.context).to be(nil)
      end
    end

    context "and the 'Content-Type' includes 'text/html'" do
      let(:content_type) { 'text/html; charset=UTF-8' }

      context "and the response body contains the unescaped HTML test string" do
        let(:response_body) do
          <<~HTML
          <html>
            <body>
              <p>example content</p>
              <p>#{original_value}#{random_value1}#{test_string}#{random_value2}</p>
              <p>more content</p>
            </body>
          </html>
          HTML
        end

        let(:wrapped_test_string) do
          test_string.wrap(random_value1,random_value2)
        end
        let(:match_data) do
          wrapped_test_string.match(response_body)
        end

        it "must return true" do
          expect(subject.vulnerable?).to be(true)
        end

        it "must populate #allowed_chars with the unescaped characters" do
          subject.vulnerable?

          expect(subject.allowed_chars).to be_kind_of(Set)
          expect(subject.allowed_chars.to_a).to eq(
            ["'", '"', '=', ' ', '/', '>', '<']
          )
        end

        it "must set #context "do
          subject.vulnerable?

          expect(subject.context).to be_kind_of(described_class::Context)
        end

        context "and the HTML test string occurs within a HTML tag's body" do
          it "must set #context.location to :tag_body" do
            subject.vulnerable?

            expect(subject.context.location).to be(:tag_body)
          end

          it "must set #context.tag to the tag's name" do
            subject.vulnerable?

            expect(subject.context.tag).to eq('p')
          end

          it "must not set #context.attr" do
            subject.vulnerable?

            expect(subject.context.attr).to be(nil)
          end

          context "but the '\\'' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p>#{original_value}#{random_value1}&#39;"= /><#{random_value2}</p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\\'' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include("'")
            end
          end

          context "but the '\\'' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p>#{original_value}#{random_value1}%27"= /><#{random_value2}</p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\\'' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include("'")
            end
          end

          context "but the '\\'' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p>#{original_value}#{random_value1}"= /><#{random_value2}</p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\\'' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include("'")
            end
          end

          context "but the '\"' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p>#{original_value}#{random_value1}'&quot;= /><#{random_value2}</p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\"' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('"')
            end
          end

          context "but the '\"' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p>#{original_value}#{random_value1}'= /><#{random_value2}</p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\"' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('"')
            end
          end

          context "but the '=' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p>#{original_value}#{random_value1}'"%3D /><#{random_value2}</p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '=' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('=')
            end
          end

          context "but the '=' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p>#{original_value}#{random_value1}'" /><#{random_value2}</p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '=' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('=')
            end
          end

          context "but the '>' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p>#{original_value}#{random_value1}'"= /&gt;<#{random_value2}</p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '>' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('>')
            end
          end

          context "but the '>' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p>#{original_value}#{random_value1}'"= /%3E<#{random_value2}</p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '>' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('>')
            end
          end

          context "but the '>' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p>#{original_value}#{random_value1}'"= /<#{random_value2}</p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '>' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('>')
            end
          end

          context "but the ' ' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p>#{original_value}#{random_value1}'"=&nbsp;/><#{random_value2}</p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include ' ' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include(' ')
            end
          end

          context "but the ' ' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p>#{original_value}#{random_value1}'"=%20/><#{random_value2}</p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include ' ' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include(' ')
            end
          end

          context "but the ' ' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p>#{original_value}#{random_value1}'"=/><#{random_value2}</p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include ' ' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include(' ')
            end
          end

          context "but the '/' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p>#{original_value}#{random_value1}'"= %2F><#{random_value2}</p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '/' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('/')
            end
          end

          context "but the '/' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p>#{original_value}#{random_value1}'"= ><#{random_value2}</p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '/' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('/')
            end
          end

          context "but the '<' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p>#{original_value}#{random_value1}'"= />&lt;#{random_value2}</p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '<' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('<')
            end
          end

          context "but the '<' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p>#{original_value}#{random_value1}'"= />%3C#{random_value2}</p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '<' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('<')
            end
          end

          context "but the '<' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p>#{original_value}#{random_value1}'"= />#{random_value2}</p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '<' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('<')
            end
          end
        end

        context "and the HTML test string occurs within a HTML attribute's double-quoted value" do
          let(:response_body) do
            <<~HTML
            <html>
              <body>
                <p>example content</p>
                <p attr="#{original_value}#{random_value1}#{test_string}#{random_value2}"></p>
                <p>more content</p>
              </body>
            </html>
            HTML
          end

          it "must set #context.location to :double_quted_attr_value" do
            subject.vulnerable?

            expect(subject.context.location).to be(:double_quoted_attr_value)
          end

          it "must set #context.tag to the parent tag's name" do
            subject.vulnerable?

            expect(subject.context.tag).to eq('p')
          end

          it "must set #context.attr to the attribute's name" do
            subject.vulnerable?

            expect(subject.context.attr).to eq('attr')
          end

          context "but the '\\'' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr="#{original_value}#{random_value1}&#39;"= /><#{random_value2}"></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\\'' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include("'")
            end
          end

          context "but the '\\'' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr="#{original_value}#{random_value1}%27"= /><#{random_value2}"></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\\'' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include("'")
            end
          end

          context "but the '\\'' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr="#{original_value}#{random_value1}"= /><#{random_value2}"></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\\'' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include("'")
            end
          end

          context "but the '\"' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr="#{original_value}#{random_value1}'&quot;= /><#{random_value2}"></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '\"' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('"')
            end
          end

          context "but the '\"' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr="#{original_value}#{random_value1}'= /><#{random_value2}"></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '\"' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('"')
            end
          end

          context "but the '=' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr="#{original_value}#{random_value1}'"%3D /><#{random_value2}"></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '=' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('=')
            end
          end

          context "but the '=' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr="#{original_value}#{random_value1}'" /><#{random_value2}"></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '=' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('=')
            end
          end

          context "but the '>' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr="#{original_value}#{random_value1}'"= /&gt;<#{random_value2}"></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '>' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('>')
            end
          end

          context "but the '>' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr="#{original_value}#{random_value1}'"= /%3E<#{random_value2}"></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '>' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('>')
            end
          end

          context "but the '>' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr="#{original_value}#{random_value1}'"= /<#{random_value2}"></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '>' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('>')
            end
          end

          context "but the ' ' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr="#{original_value}#{random_value1}'"=&nbsp;/><#{random_value2}"></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include ' ' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include(' ')
            end
          end

          context "but the ' ' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr="#{original_value}#{random_value1}'"=%20/><#{random_value2}"></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include ' ' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include(' ')
            end
          end

          context "but the ' ' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr="#{original_value}#{random_value1}'"=/><#{random_value2}"></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include ' ' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include(' ')
            end
          end

          context "but the '/' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr="#{original_value}#{random_value1}'"= %2F><#{random_value2}"></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '/' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('/')
            end
          end

          context "but the '/' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr="#{original_value}#{random_value1}'"= ><#{random_value2}"></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '/' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('/')
            end
          end

          context "but the '<' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr="#{original_value}#{random_value1}'"= />&lt;#{random_value2}"></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '<' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('<')
            end
          end

          context "but the '<' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr="#{original_value}#{random_value1}'"= />%3C#{random_value2}"></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '<' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('<')
            end
          end

          context "but the '<' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr="#{original_value}#{random_value1}'"= />#{random_value2}"></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '<' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('<')
            end
          end
        end

        context "and the HTML test string occurs within a HTML attribute's single-quoted value" do
          let(:response_body) do
            <<~HTML
            <html>
              <body>
                <p>example content</p>
                <p attr='#{original_value}#{random_value1}#{test_string}#{random_value2}'></p>
                <p>more content</p>
              </body>
            </html>
            HTML
          end

          it "must set #context.location to :single_quted_attr_value" do
            subject.vulnerable?

            expect(subject.context.location).to be(:single_quoted_attr_value)
          end

          it "must set #context.tag to the parent tag's name" do
            subject.vulnerable?

            expect(subject.context.tag).to eq('p')
          end

          it "must set #context.attr to the attribute's name" do
            subject.vulnerable?

            expect(subject.context.attr).to eq('attr')
          end

          context "but the '\\'' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}&#39;"= /><#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '\\'' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include("'")
            end
          end

          context "but the '\\'' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}%27"= /><#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '\\'' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include("'")
            end
          end

          context "but the '\\'' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}"= /><#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '\\'' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include("'")
            end
          end

          context "but the '\"' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'&quot;= /><#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\"' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('"')
            end
          end

          context "but the '\"' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'= /><#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\"' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('"')
            end
          end

          context "but the '=' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'"%3D /><#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '=' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('=')
            end
          end

          context "but the '=' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'" /><#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '=' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('=')
            end
          end

          context "but the '>' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'"= /&gt;<#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '>' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('>')
            end
          end

          context "but the '>' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'"= /%3E<#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '>' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('>')
            end
          end

          context "but the '>' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'"= /<#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '>' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('>')
            end
          end

          context "but the ' ' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'"=&nbsp;/><#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include ' ' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include(' ')
            end
          end

          context "but the ' ' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'"=%20/><#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include ' ' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include(' ')
            end
          end

          context "but the ' ' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'"=/><#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include ' ' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include(' ')
            end
          end

          context "but the '/' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'"= %2F><#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '/' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('/')
            end
          end

          context "but the '/' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'"= ><#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '/' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('/')
            end
          end

          context "but the '<' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'"= />&lt;#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '<' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('<')
            end
          end

          context "but the '<' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'"= />%3C#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '<' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('<')
            end
          end

          context "but the '<' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'"= />#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '<' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('<')
            end
          end
        end

        context "and the HTML test string occurs within a HTML attribute's unquoted value" do
          let(:response_body) do
            <<~HTML
            <html>
              <body>
                <p>example content</p>
                <p attr=#{original_value}#{random_value1}#{test_string}#{random_value2}></p>
                <p>more content</p>
              </body>
            </html>
            HTML
          end

          it "must set #context.location to :unquted_attr_value" do
            subject.vulnerable?

            expect(subject.context.location).to be(:unquoted_attr_value)
          end

          it "must set #context.tag to the parent tag's name" do
            subject.vulnerable?

            expect(subject.context.tag).to eq('p')
          end

          it "must set #context.attr to the attribute's name" do
            subject.vulnerable?

            expect(subject.context.attr).to eq('attr')
          end

          context "but the '\\'' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr=#{original_value}#{random_value1}&#39;"= /><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\\'' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include("'")
            end
          end

          context "but the '\\'' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr=#{original_value}#{random_value1}%27"= /><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\\'' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include("'")
            end
          end

          context "but the '\\'' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr=#{original_value}#{random_value1}"= /><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\\'' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include("'")
            end
          end

          context "but the '\"' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'&quot;= /><#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\"' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('"')
            end
          end

          context "but the '\"' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'= /><#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\"' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('"')
            end
          end

          context "but the '=' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'"%3D /><#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '=' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('=')
            end
          end

          context "but the '=' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'" /><#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '=' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('=')
            end
          end

          context "but the '>' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'"= /&gt;<#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '>' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('>')
            end
          end

          context "but the '>' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'"= /%3E<#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '>' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('>')
            end
          end

          context "but the '>' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'"= /<#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '>' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('>')
            end
          end

          context "but the ' ' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'"=&nbsp;/><#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include ' ' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include(' ')
            end
          end

          context "but the ' ' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'"=%20/><#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include ' ' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include(' ')
            end
          end

          context "but the ' ' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'"=/><#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include ' ' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include(' ')
            end
          end

          context "but the '/' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'"= %2F><#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '/' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('/')
            end
          end

          context "but the '/' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'"= ><#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '/' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('/')
            end
          end

          context "but the '<' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'"= />&lt;#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '<' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('<')
            end
          end

          context "but the '<' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'"= />%3C#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '<' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('<')
            end
          end

          context "but the '<' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr='#{original_value}#{random_value1}'"= />#{random_value2}'></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '<' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('<')
            end
          end
        end

        context "and the HTML test string occurs within a HTML attribute's name" do
          let(:response_body) do
            <<~HTML
            <html>
              <body>
                <p>example content</p>
                <p attr#{original_value}#{random_value1}#{test_string}#{random_value2}></p>
                <p>more content</p>
              </body>
            </html>
            HTML
          end

          it "must set #context.location to :attr_name" do
            subject.vulnerable?

            expect(subject.context.location).to be(:attr_name)
          end

          it "must set #context.tag to the parent tag's name" do
            subject.vulnerable?

            expect(subject.context.tag).to eq('p')
          end

          it "must set #context.attr to the attribute's name" do
            subject.vulnerable?

            expect(subject.context.attr).to eq("attr#{original_value}")
          end

          context "but the '\\'' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr#{original_value}#{random_value1}&#39;"= /><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\\'' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include("'")
            end
          end

          context "but the '\\'' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr#{original_value}#{random_value1}%27"= /><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\\'' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include("'")
            end
          end

          context "but the '\\'' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr#{original_value}#{random_value1}"= /><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\\'' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include("'")
            end
          end

          context "but the '\"' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr#{original_value}#{random_value1}'&quot;= /><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\"' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('"')
            end
          end

          context "but the '\"' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr#{original_value}#{random_value1}'= /><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\"' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('"')
            end
          end

          context "but the '=' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr#{original_value}#{random_value1}'"%3D /><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '=' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('=')
            end
          end

          context "but the '=' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr#{original_value}#{random_value1}'" /><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '=' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('=')
            end
          end

          context "but the '>' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr#{original_value}#{random_value1}'"= /&gt;<#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '>' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('>')
            end
          end

          context "but the '>' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr#{original_value}#{random_value1}'"= /%3E<#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '>' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('>')
            end
          end

          context "but the '>' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr#{original_value}#{random_value1}'"= /<#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '>' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('>')
            end
          end

          context "but the ' ' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr#{original_value}#{random_value1}'"=&nbsp;/><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include ' ' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include(' ')
            end
          end

          context "but the ' ' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr#{original_value}#{random_value1}'"=%20/><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include ' ' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include(' ')
            end
          end

          context "but the ' ' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr#{original_value}#{random_value1}'"=/><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include ' ' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include(' ')
            end
          end

          context "but the '/' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr#{original_value}#{random_value1}'"= %2F><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '/' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('/')
            end
          end

          context "but the '/' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr#{original_value}#{random_value1}'"= ><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '/' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('/')
            end
          end

          context "but the '<' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr#{original_value}#{random_value1}'"= />&lt;#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '<' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('<')
            end
          end

          context "but the '<' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr#{original_value}#{random_value1}'"= />%3C#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '<' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('<')
            end
          end

          context "but the '<' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p attr#{original_value}#{random_value1}'"= />#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '<' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('<')
            end
          end
        end

        context "and the HTML test string occurs within a HTML attribute's list" do
          let(:response_body) do
            <<~HTML
            <html>
              <body>
                <p>example content</p>
                <p #{random_value1}#{test_string}#{random_value2}></p>
                <p>more content</p>
              </body>
            </html>
            HTML
          end

          it "must set #context.location to :attr_list" do
            subject.vulnerable?

            expect(subject.context.location).to be(:attr_list)
          end

          it "must set #context.tag to the parent tag's name" do
            subject.vulnerable?

            expect(subject.context.tag).to eq('p')
          end

          it "must not set #context.attr" do
            subject.vulnerable?

            expect(subject.context.attr).to be(nil)
          end

          context "but the '\\'' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p #{original_value}#{random_value1}&#39;"= /><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\\'' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include("'")
            end
          end

          context "but the '\\'' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p #{original_value}#{random_value1}%27"= /><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\\'' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include("'")
            end
          end

          context "but the '\\'' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p #{original_value}#{random_value1}"= /><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\\'' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include("'")
            end
          end

          context "but the '\"' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p #{original_value}#{random_value1}'&quot;= /><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\"' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('"')
            end
          end

          context "but the '\"' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p #{original_value}#{random_value1}'= /><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\"' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('"')
            end
          end

          context "but the '=' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p #{original_value}#{random_value1}'"%3D /><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '=' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('=')
            end
          end

          context "but the '=' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p #{original_value}#{random_value1}'" /><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '=' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('=')
            end
          end

          context "but the '>' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p #{original_value}#{random_value1}'"= /&gt;<#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '>' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('>')
            end
          end

          context "but the '>' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p #{original_value}#{random_value1}'"= /%3E<#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '>' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('>')
            end
          end

          context "but the '>' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p #{original_value}#{random_value1}'"= /<#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '>' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('>')
            end
          end

          context "but the ' ' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p #{original_value}#{random_value1}'"=&nbsp;/><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include ' ' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include(' ')
            end
          end

          context "but the ' ' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p #{original_value}#{random_value1}'"=%20/><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include ' ' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include(' ')
            end
          end

          context "but the ' ' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p #{original_value}#{random_value1}'"=/><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include ' ' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include(' ')
            end
          end

          context "but the '/' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p #{original_value}#{random_value1}'"= %2F><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '/' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('/')
            end
          end

          context "but the '/' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p #{original_value}#{random_value1}'"= ><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '/' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('/')
            end
          end

          context "but the '<' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p #{original_value}#{random_value1}'"= />&lt;#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '<' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('<')
            end
          end

          context "but the '<' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p #{original_value}#{random_value1}'"= />%3C#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '<' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('<')
            end
          end

          context "but the '<' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p #{original_value}#{random_value1}'"= />#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '<' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('<')
            end
          end
        end

        context "and the HTML test string occurs within a HTML tag name" do
          let(:response_body) do
            <<~HTML
            <html>
              <body>
                <p>example content</p>
                <p#{random_value1}#{test_string}#{random_value2}></p>
                <p>more content</p>
              </body>
            </html>
            HTML
          end

          it "must set #context.location to :tag_name" do
            subject.vulnerable?

            expect(subject.context.location).to be(:tag_name)
          end

          it "must set #context.tag to the parent tag's name" do
            subject.vulnerable?

            expect(subject.context.tag).to eq('p')
          end

          it "must not set #context.attr" do
            subject.vulnerable?

            expect(subject.context.attr).to be(nil)
          end

          context "but the '\\'' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p#{original_value}#{random_value1}&#39;"= /><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\\'' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include("'")
            end
          end

          context "but the '\\'' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p#{original_value}#{random_value1}%27"= /><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\\'' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include("'")
            end
          end

          context "but the '\\'' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p#{original_value}#{random_value1}"= /><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\\'' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include("'")
            end
          end

          context "but the '\"' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p#{original_value}#{random_value1}'&quot;= /><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\"' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('"')
            end
          end

          context "but the '\"' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p#{original_value}#{random_value1}'= /><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '\"' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('"')
            end
          end

          context "but the '=' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p#{original_value}#{random_value1}'"%3D /><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '=' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('=')
            end
          end

          context "but the '=' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p#{original_value}#{random_value1}'" /><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be(true)
            end

            it "must not include '=' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('=')
            end
          end

          context "but the '>' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p#{original_value}#{random_value1}'"= /&gt;<#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '>' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('>')
            end
          end

          context "but the '>' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p#{original_value}#{random_value1}'"= /%3E<#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '>' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('>')
            end
          end

          context "but the '>' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p#{original_value}#{random_value1}'"= /<#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '>' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('>')
            end
          end

          context "but the ' ' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p#{original_value}#{random_value1}'"=&nbsp;/><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include ' ' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include(' ')
            end
          end

          context "but the ' ' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p#{original_value}#{random_value1}'"=%20/><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include ' ' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include(' ')
            end
          end

          context "but the ' ' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p#{original_value}#{random_value1}'"=/><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include ' ' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include(' ')
            end
          end

          context "but the '/' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p#{original_value}#{random_value1}'"= %2F><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '/' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('/')
            end
          end

          context "but the '/' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p#{original_value}#{random_value1}'"= ><#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '/' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('/')
            end
          end

          context "but the '<' character was HTML escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p#{original_value}#{random_value1}'"= />&lt;#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '<' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('<')
            end
          end

          context "but the '<' character was URI escaped" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p#{original_value}#{random_value1}'"= />%3C#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '<' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('<')
            end
          end

          context "but the '<' character was filtered" do
            let(:response_body) do
              <<~HTML
              <html>
                <body>
                  <p>example content</p>
                  <p#{original_value}#{random_value1}'"= />#{random_value2}></p>
                  <p>more content</p>
                </body>
              </html>
              HTML
            end

            it "must return false" do
              expect(subject.vulnerable?).to be(false)
            end

            it "must not include '<' in #allowed_chars" do
              subject.vulnerable?

              expect(subject.allowed_chars).to_not include('<')
            end
          end
        end
      end

      context "and the response body does not contain the HTML test string" do
        it "must not yield anything" do
          expect(subject.vulnerable?).to be(false)
        end

        it "must not set #allowed_chars" do
          subject.vulnerable?

          expect(subject.allowed_chars).to be(nil)
        end

        it "must not set #context" do
          subject.vulnerable?

          expect(subject.context).to be(nil)
        end
      end
    end

    context "and the 'Content-Type' does not include 'text/html'" do
      let(:content_type) { 'text/xml' }

      it "must not yield anything" do
        expect(subject.vulnerable?).to be(false)
      end

      it "must not set #allowed_chars" do
        subject.vulnerable?

        expect(subject.allowed_chars).to be(nil)
      end

      it "must not set #context" do
        subject.vulnerable?

        expect(subject.context).to be(nil)
      end
    end
  end
end
