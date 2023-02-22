require 'spec_helper'
require 'web_vuln_examples'
require 'ronin/vulns/sqli'

require 'webmock/rspec'

describe Ronin::Vulns::SQLI do
  describe ".vuln_type" do
    subject { described_class }

    it "must return :sqli" do
      expect(subject.vuln_type).to eq(:sqli)
    end
  end

  describe "#initialize" do
    include_examples "Ronin::Vulns::WebVuln#initialize examples"

    it "must default #escape_quote to false" do
      expect(subject.escape_quote).to be(false)
    end

    it "must default #escape_parens to false" do
      expect(subject.escape_parens).to be(false)
    end

    it "must default #terminate to false" do
      expect(subject.terminate).to be(false)
    end

    context "when given the escape_quote: keyword is given" do
      subject do
        described_class.new(url, query_param:  query_param,
                                 escape_quote: true)
      end

      it "must set #escape_quote to true" do
        expect(subject.escape_quote).to be(true)
      end
    end

    context "when given the escape_parens: keyword is given" do
      subject do
        described_class.new(url, query_param:   query_param,
                                 escape_parens: true)
      end

      it "must set #escape_parens to true" do
        expect(subject.escape_parens).to be(true)
      end
    end

    context "when given the terminate: keyword is given" do
      subject do
        described_class.new(url, query_param: query_param,
                                 terminate:   true)
      end

      it "must set #terminate to true" do
        expect(subject.terminate).to be(true)
      end
    end
  end

  describe ".scan" do
    subject { described_class }

    let(:url) { "https://example.com/page?foo=1&bar=2&baz=3" }
  end

  let(:query_param)    { 'bar' }
  let(:original_value) { '2' }

  let(:url) do
    "https://example.com/page?foo=1&#{query_param}=#{original_value}&baz=3"
  end

  subject { described_class.new(url, query_param: query_param) }

  describe "#escape" do
    let(:sql) { 'OR 1=1' }

    context "when #escape_quote is true" do
      subject do
        described_class.new(url, query_param:  query_param,
                                 escape_quote: true)
      end

      it "must return the \"\#{original_value}' ...\"" do
        expect(subject.escape(sql)).to eq("#{subject.original_value}' #{sql}")
      end

      context "and the SQL value ends with a \"'\"" do
        let(:sql) { "OR '1'='1'" }

        it "must remove the \"'\" character at the end of the SQL string" do
          expect(subject.escape(sql)).to eq("#{subject.original_value}' #{sql[0..-2]}")
        end
      end

      context "but the SQL value starts with a ';'" do
        let(:sql) { ";SELECT 1" }

        it "must return the \"\#{original_value}';...\"" do
          expect(subject.escape(sql)).to eq("#{subject.original_value}'#{sql}")
        end
      end

      context "and #terminate is true" do
        subject do
          described_class.new(url, query_param:  query_param,
                                   escape_quote: true,
                                   terminate:    true)
        end

        it "must append '--' to the en of the SQL string" do
          expect(subject.escape(sql)).to eq("#{subject.original_value}' #{sql}--")
        end
      end
    end

    context "when #escape_parens is true" do
      subject do
        described_class.new(url, query_param:   query_param,
                                 escape_parens: true)
      end

      it "must return the \"\#{original_value}) ...\"" do
        expect(subject.escape(sql)).to eq("#{subject.original_value}) #{sql}")
      end

      context "and the SQL value ends with a \")\"" do
        let(:sql) { "OR (1=1)" }

        it "must remove the \")\" character at the end of the SQL string" do
          expect(subject.escape(sql)).to eq("#{subject.original_value}) #{sql[0..-2]}")
        end
      end

      context "but the SQL value starts with a ';'" do
        let(:sql) { ";SELECT 1" }

        it "must return the \"\#{original_value});...\"" do
          expect(subject.escape(sql)).to eq("#{subject.original_value})#{sql}")
        end
      end

      context "and #terminate is true" do
        subject do
          described_class.new(url, query_param:   query_param,
                                   escape_parens: true,
                                   terminate:     true)
        end

        it "must append '--' to the en of the SQL string" do
          expect(subject.escape(sql)).to eq("#{subject.original_value}) #{sql}--")
        end
      end
    end

    context "when #escape_quote and #escape_parens is true" do
      subject do
        described_class.new(url, query_param:   query_param,
                                 escape_quote:  true,
                                 escape_parens: true)
      end

      it "must return the \"\#{original_value}') ...\"" do
        expect(subject.escape(sql)).to eq("#{subject.original_value}') #{sql}")
      end

      context "and the SQL value ends with a \"')\"" do
        let(:sql) { "OR ('1'='1')" }

        it "must remove the \"')\" at the end of the SQL string" do
          expect(subject.escape(sql)).to eq("#{subject.original_value}') #{sql[0..-3]}")
        end
      end

      context "but the SQL value starts with a ';'" do
        let(:sql) { ";SELECT 1" }

        it "must return the \"\#{original_value}');...\"" do
          expect(subject.escape(sql)).to eq("#{subject.original_value}')#{sql}")
        end
      end

      context "and #terminate is true" do
        subject do
          described_class.new(url, query_param:   query_param,
                                   escape_quote:  true,
                                   escape_parens: true,
                                   terminate:     true)
        end

        it "must append '--' to the en of the SQL string" do
          expect(subject.escape(sql)).to eq("#{subject.original_value}') #{sql}--")
        end
      end
    end
  end

  describe "#encode_payload" do
    let(:sql) { 'OR 1=1' }

    it "must call #escape with the SQL value" do
      expect(subject.encode_payload(sql)).to eq(subject.escape(sql))
    end
  end

  describe "#random_id" do
    it "must return a random four digit number" do
      expect(subject.random_id).to be_between(1_000, 10_000)
    end
  end

  let(:normal_response_body) do
    <<~HTML
      <html>
        <body>
          <p>example content</p>
          <table>
            <tr>
              <th>ID</th>
              <th>Value</th>
            </tr>
            <tr>
              <td>1</td>
              <td>Foo</td>
            </tr>
          </table>
        </body>
      </html>
    HTML
  end

  let(:sql_error) { "PostgreSQL bla bla bla ERROR" }
  let(:sql_error_response_body) do
    <<~HTML
      <html>
        <body>
          <table>
            <tr>
              <th>ID</th>
              <th>Value</th>
            </tr>
            #{sql_error} bla bla bla
          </table>
        </body>
      </html>
    HTML
  end

  describe "#test_or_true_and_false" do
    let(:same_id)  { 1234 }
    let(:diff_id1) { 1111 }
    let(:diff_id2) { 2222 }

    let(:or_true)   { "#{original_value}%20OR%20#{same_id}=#{same_id}"    }
    let(:and_false) { "#{original_value}%20AND%20#{diff_id1}=#{diff_id2}" }

    before do
      allow(subject).to receive(:random_id).and_return(
        same_id,
        diff_id1,
        diff_id2
      )
    end

    it "must send a request containing ' OR id=id' then another request containing ' AND id1=id2'" do
      stub_request(:get,"https://example.com/page?#{query_param}=#{or_true}&baz=3&foo=1")
      stub_request(:get,"https://example.com/page?#{query_param}=#{and_false}&baz=3&foo=1")

      subject.test_or_true_and_false
    end

    context "when the first response is 500" do
      context "and it contains a SQL error" do
        it "must return true" do
          stub_request(:get,"https://example.com/page?#{query_param}=#{or_true}&baz=3&foo=1").to_return(status: 500, body: sql_error_response_body)
          stub_request(:get,"https://example.com/page?#{query_param}=#{and_false}&baz=3&foo=1")

          expect(subject.test_or_true_and_false).to be(true)
        end
      end
    end

    context "when the second response is 500" do
      context "when the second response contains a SQL error" do
        it "must return true" do
          stub_request(:get,"https://example.com/page?#{query_param}=#{or_true}&baz=3&foo=1")
          stub_request(:get,"https://example.com/page?#{query_param}=#{and_false}&baz=3&foo=1").to_return(status: 500, body: sql_error_response_body)

          expect(subject.test_or_true_and_false).to be(true)
        end
      end
    end

    context "when the two responses are both 200" do
      context "but the first response is larger than the second response" do
        let(:response_body1) do
          <<~HTML
            <html>
              <body>
                <p>example content</p>
                <table>
                  <tr>
                    <th>ID</th>
                    <th>Value</th>
                  </tr>
                  <tr>
                    <td>1</td>
                    <td>Foo</td>
                  </tr>
                  <tr>
                    <td>2</td>
                    <td>Bar</td>
                  </tr>
                  <tr>
                    <td>3</td>
                    <td>Baz</td>
                  </tr>
                </table>
                <p>more content</p>
              </body>
            </html>
          HTML
        end

        let(:response_body2) do
          <<~HTML
            <html>
              <body>
                <p>example content</p>
                <table>
                  <tr>
                    <th>ID</th>
                    <th>Value</th>
                  </tr>
                </table>
                <p>more content</p>
              </body>
            </html>
          HTML
        end

        it "must return true" do
          stub_request(:get,"https://example.com/page?#{query_param}=#{or_true}&baz=3&foo=1").to_return(status: 200, body: response_body1)
          stub_request(:get,"https://example.com/page?#{query_param}=#{and_false}&baz=3&foo=1").to_return(status: 200, body: response_body2)

          expect(subject.test_or_true_and_false).to be(true)
        end
      end

      context "but the first response is the same size as the second response" do
        it "must return false" do
          stub_request(:get,"https://example.com/page?#{query_param}=#{or_true}&baz=3&foo=1").to_return(status: 200, body: normal_response_body)
          stub_request(:get,"https://example.com/page?#{query_param}=#{and_false}&baz=3&foo=1").to_return(status: 200, body: normal_response_body)

          expect(subject.test_or_true_and_false).to be(false)
        end
      end

      context "but the first response is smaller than the second response" do
        let(:response_body1) do
          <<~HTML
            <html>
              <body>
                <p>example content</p>
                <table>
                  <tr>
                    <th>ID</th>
                    <th>Value</th>
                  </tr>
                </table>
                <p>more content</p>
              </body>
            </html>
          HTML
        end

        let(:response_body2) do
          <<~HTML
            <html>
              <body>
                <p>example content</p>
                <table>
                  <tr>
                    <th>ID</th>
                    <th>Value</th>
                  </tr>
                  <tr>
                    <td>1</td>
                    <td>Foo</td>
                  </tr>
                  <tr>
                    <td>2</td>
                    <td>Bar</td>
                  </tr>
                  <tr>
                    <td>3</td>
                    <td>Baz</td>
                  </tr>
                </table>
                <p>more content</p>
              </body>
            </html>
          HTML
        end

        it "must return false" do
          stub_request(:get,"https://example.com/page?#{query_param}=#{or_true}&baz=3&foo=1").to_return(status: 200, body: response_body1)
          stub_request(:get,"https://example.com/page?#{query_param}=#{and_false}&baz=3&foo=1").to_return(status: 200, body: response_body2)

          expect(subject.test_or_true_and_false).to be(false)
        end
      end
    end

    context "when the first responses is 200 but the second response is 404" do
      let(:response_body1) do
        <<~HTML
          <html>
            <body>
              <p>example content</p>
              <table>
                <tr>
                  <th>ID</th>
                  <th>Value</th>
                </tr>
                <tr>
                  <td>1</td>
                  <td>Foo</td>
                </tr>
                <tr>
                  <td>2</td>
                  <td>Bar</td>
                </tr>
                <tr>
                  <td>3</td>
                  <td>Baz</td>
                </tr>
              </table>
              <p>more content</p>
            </body>
          </html>
        HTML
      end

      let(:response_body2) do
        <<~HTML
          <html>
            <body>
              <h1>Not Found</h1>
              <p>could not find the record with the given ID: #{and_false}</p>
            </body>
          </html>
        HTML
      end

      it "must return true" do
        stub_request(:get,"https://example.com/page?#{query_param}=#{or_true}&baz=3&foo=1").to_return(status: 200, body: response_body1)
        stub_request(:get,"https://example.com/page?#{query_param}=#{and_false}&baz=3&foo=1").to_return(status: 404, body: response_body2)

        expect(subject.test_or_true_and_false).to be(true)
      end
    end

    context "when the first responses is 200 but the second response is 500" do
      let(:response_body1) do
        <<~HTML
          <html>
            <body>
              <p>example content</p>
              <table>
                <tr>
                  <th>ID</th>
                  <th>Value</th>
                </tr>
                <tr>
                  <td>1</td>
                  <td>Foo</td>
                </tr>
                <tr>
                  <td>2</td>
                  <td>Bar</td>
                </tr>
                <tr>
                  <td>3</td>
                  <td>Baz</td>
                </tr>
              </table>
              <p>more content</p>
            </body>
          </html>
        HTML
      end

      let(:response_body2) do
        <<~HTML
          <html>
            <body>
              <h1>Internal Server Error</h1>
              <p>And internal server error occurred.</p>
            </body>
          </html>
        HTML
      end

      it "must return true" do
        stub_request(:get,"https://example.com/page?#{query_param}=#{or_true}&baz=3&foo=1").to_return(status: 200, body: response_body1)
        stub_request(:get,"https://example.com/page?#{query_param}=#{and_false}&baz=3&foo=1").to_return(status: 500, body: response_body2)

        expect(subject.test_or_true_and_false).to be(true)
      end
    end
  end

  describe "#test_sleep" do
    it "must send a series of requests containing different SQL sleep commands" do
      stub_request(:get,"https://example.com/page?#{query_param}=#{original_value} SLEEP(5)&baz=3&foo=1")
      stub_request(:get,"https://example.com/page?#{query_param}=#{original_value} PG_SLEEP(5)&baz=3&foo=1")
      stub_request(:get,"https://example.com/page?#{query_param}=#{original_value} WAITFOR DELAY '0:0:5'&baz=3&foo=1")
      stub_request(:get,"https://example.com/page?#{query_param}=#{original_value};SELECT SLEEP(5)&baz=3&foo=1")
      stub_request(:get,"https://example.com/page?#{query_param}=#{original_value};SELECT PG_SLEEP(5)&baz=3&foo=1")
      stub_request(:get,"https://example.com/page?#{query_param}=#{original_value};SELECT WAITFOR DELAY '0:0:5'&baz=3&foo=1")

      subject.test_sleep
    end

    context "when one of the responses is 500" do
      context "and it contains SQL errors" do
        it "must return true" do
          stub_request(:get,"https://example.com/page?#{query_param}=#{original_value} SLEEP(5)&baz=3&foo=1")
          stub_request(:get,"https://example.com/page?#{query_param}=#{original_value} PG_SLEEP(5)&baz=3&foo=1").and_return(status: 500, body: sql_error_response_body)
          stub_request(:get,"https://example.com/page?#{query_param}=#{original_value} WAITFOR DELAY '0:0:5'&baz=3&foo=1")
          stub_request(:get,"https://example.com/page?#{query_param}=#{original_value};SELECT SLEEP(5)&baz=3&foo=1")
          stub_request(:get,"https://example.com/page?#{query_param}=#{original_value};SELECT PG_SLEEP(5)&baz=3&foo=1")
          stub_request(:get,"https://example.com/page?#{query_param}=#{original_value};SELECT WAITFOR DELAY '0:0:5'&baz=3&foo=1")

          expect(subject.test_sleep).to be(true)
        end
      end
    end

    context "when none of the responses take at most 5 seconds to complete" do
      it "must return false" do
        stub_request(:get,"https://example.com/page?#{query_param}=#{original_value} SLEEP(5)&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?#{query_param}=#{original_value} PG_SLEEP(5)&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?#{query_param}=#{original_value} WAITFOR DELAY '0:0:5'&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?#{query_param}=#{original_value};SELECT SLEEP(5)&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?#{query_param}=#{original_value};SELECT PG_SLEEP(5)&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?#{query_param}=#{original_value};SELECT WAITFOR DELAY '0:0:5'&baz=3&foo=1")

        expect(subject.test_sleep).to be(false)
      end
    end

    context "when one of the responses takes more than 5 seconds to complete" do
      it "must return true" do
        time = Time.now

        allow(Time).to receive(:now).and_return(
          time,
          # request 1
          time+1, # 1 second later
          time+1.1,
          # request 2
          time+6.2, # 5.1 seconds later
          time+6.3,
          # request 3
          time+7.3, # 1 second later
          time+7.4,
          # request 4
          time+8.4, # 1 second later
          time+8.5,
          # request 5
          time+9.5, # 1 second later
          time+9.6,
          # request 6
          time+10.6 # 1 second later
        )

        stub_request(:get,"https://example.com/page?#{query_param}=#{original_value} SLEEP(5)&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?#{query_param}=#{original_value} PG_SLEEP(5)&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?#{query_param}=#{original_value} WAITFOR DELAY '0:0:5'&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?#{query_param}=#{original_value};SELECT SLEEP(5)&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?#{query_param}=#{original_value};SELECT PG_SLEEP(5)&baz=3&foo=1")
        stub_request(:get,"https://example.com/page?#{query_param}=#{original_value};SELECT WAITFOR DELAY '0:0:5'&baz=3&foo=1")

        expect(subject.test_sleep).to be(true)
      end
    end
  end

  describe "#vulnerable?" do
    it "must call #test_or_true_and_false then #test_sleep" do
      expect(subject).to receive(:test_or_true_and_false)
      expect(subject).to receive(:test_sleep)

      subject.vulnerable?
    end

    context "when #test_or_true_and_false returns true" do
      it "must return true" do
        expect(subject).to receive(:test_or_true_and_false).and_return(true)

        expect(subject.vulnerable?).to be(true)
      end

      it "must not call #test_sleep" do
        expect(subject).to receive(:test_or_true_and_false).and_return(true)
        expect(subject).to_not receive(:test_sleep)

        expect(subject.vulnerable?).to be(true)
      end
    end

    context "when #test_or_true_and_false returns false" do
      it "must call #test_sleep next" do
        expect(subject).to receive(:test_or_true_and_false).and_return(false)
        expect(subject).to receive(:test_sleep)

        subject.vulnerable?
      end

      context "and when #test_sleep returns true" do
        it "must return true" do
          expect(subject).to receive(:test_or_true_and_false).and_return(false)
          expect(subject).to receive(:test_sleep).and_return(true)

          expect(subject.vulnerable?).to be(true)
        end
      end

      context "and when #test_sleep returns false" do
        it "must return false" do
          expect(subject).to receive(:test_or_true_and_false).and_return(false)
          expect(subject).to receive(:test_sleep).and_return(false)

          expect(subject.vulnerable?).to be(false)
        end
      end
    end
  end
end
