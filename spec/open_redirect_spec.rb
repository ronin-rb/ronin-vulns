require 'spec_helper'
require 'web_vuln_examples'
require 'ronin/vulns/open_redirect'

require 'webmock/rspec'

describe Ronin::Vulns::OpenRedirect do
  describe ".vuln_type" do
    subject { described_class }

    it "must return :open_redirect" do
      expect(subject.vuln_type).to eq(:open_redirect)
    end
  end

  describe "#initialize" do
    include_examples "Ronin::Vulns::WebVuln#initialize examples"

    it "must set #test_url" do
      expect(subject.test_url).to match(%r{\Ahttps://ronin-rb\.dev/vulns/open_redirect\.html\?id=[A-Za-z0-9]+\z})
    end
  end

  describe ".random_test_url" do
    subject { described_class }

    it "must return a random 'https://ronin-rb.dev/vulns/open_redirect.html?id=...' URL" do
      expect(subject.random_test_url).to match(%r{\Ahttps://ronin-rb\.dev/vulns/open_redirect\.html\?id=[A-Za-z0-9]+\z})
    end

    it "must return a random test URL each time" do
      urls = Array.new(3) { subject.random_test_url }

      expect(urls.uniq.length).to be > 1
    end
  end

  let(:query_param) { 'bar' }
  let(:url)         { "https://example.com/page?foo=1&bar=2&baz=3" }

  subject { described_class.new(url, query_param: query_param) }

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

    let(:code) { '200' }
    let(:response) do
      double('Net::HTTPResponse', content_type: 'text/html',
                                  code:         code,
                                  body:         response_body)
    end

    before do
      expect(subject).to receive(:exploit).with(subject.test_url).and_return(response)
    end

    it "must call #exploit with #test_url" do
      subject.vulnerable?
    end

    %w[301 302 303 307 308].each do |code|
      context "when the response code is 301" do
        let(:code) { code }

        let(:response) do
          double('Net::HTTPResponse', code: code)
        end

        context "and there is a Location header" do
          context "and it equals #test_url" do
            let(:location) { subject.test_url }

            before do
              allow(response).to receive(:get_fields).with('Location').and_return([location])
            end

            it "must return true" do
              expect(subject.vulnerable?).to be_truthy
            end
          end

          context "and it starts with #test_url but with additional ?params" do
            let(:location) { "#{subject.test_url}?foo=bar" }

            before do
              allow(response).to receive(:get_fields).with('Location').and_return([location])
            end

            it "must return true" do
              expect(subject.vulnerable?).to be_truthy
            end
          end

          context "and it starts with #test_url but with additional &params" do
            let(:location) { "#{subject.test_url}&foo=bar" }

            before do
              allow(response).to receive(:get_fields).with('Location').and_return([location])
            end

            it "must return true" do
              expect(subject.vulnerable?).to be_truthy
            end
          end

          context "but it does not match #test_url" do
            let(:location) { "https://example.com/" }

            before do
              allow(response).to receive(:get_fields).with('Location').and_return([location])
            end

            it "must return false" do
              expect(subject.vulnerable?).to be_falsy
            end
          end
        end

        context "but there are multiple Location headers" do
          context "and the last Location header is the #test_url" do
            let(:locations) do
              ['http://example.com/', subject.test_url]
            end

            before do
              allow(response).to receive(:get_fields).with('Location').and_return(locations)
            end

            it "must return true" do
              expect(subject.vulnerable?).to be_truthy
            end
          end

          context "but the last Location header is not #test_url" do
            let(:locations) do
              ['http://example.com/foo', "https://example.com/bar"]
            end

            before do
              allow(response).to receive(:get_fields).with('Location').and_return(locations)
            end

            it "must return false" do
              expect(subject.vulnerable?).to be_falsy
            end
          end
        end

        context "but there is no Location header" do
          before do
            allow(response).to receive(:get_fields).with('Location').and_return(nil)
          end

          it "must return false" do
            expect(subject.vulnerable?).to be_falsy
          end
        end
      end
    end

    context "when the response code isn't a 30x" do
      let(:code) { '200' }

      let(:response) do
        double('Net::HTTPResponse', code: code, body: response_body)
      end

      context "when the response Content-Type includes 'text/html'" do
        let(:content_type) { "text/html; charset=UTF-8" }
        let(:response) do
          double('Net::HTTPResponse', code:         code,
                                      content_type: content_type,
                                      body:         response_body)
        end

        context "and the response includes a meta refresh redirect" do
          let(:response_body) do
            <<~HTML
              <html>
                <head>
                  <meta http-equiv="refresh" content="0;url='#{subject.test_url}'"/>
                </head>
                <body>
                  <p>example content</p>
                  <p>included content</p>
                  <p>more content</p>
                </body>
              </html>
            HTML
          end

          it "must return true" do
            expect(subject.vulnerable?).to be_truthy
          end

          context "when meta tag is all upercase" do
            let(:response_body) do
              <<~HTML
                <html>
                  <head>
                    <META HTTP-EQUIV="REFRESH" CONTENT="0;URL='#{subject.test_url}'"/>
                  </head>
                  <body>
                    <p>example content</p>
                    <p>included content</p>
                    <p>more content</p>
                  </body>
                </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be_truthy
            end
          end

          context "when there is a space after http-equiv attribute name" do
            let(:response_body) do
              <<~HTML
                <html>
                  <head>
                    <meta http-equiv ="refresh" content="10;url='#{subject.test_url}'"/>
                  </head>
                  <body>
                    <p>example content</p>
                    <p>included content</p>
                    <p>more content</p>
                  </body>
                </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be_truthy
            end
          end

          context "when there is a space after 'http-equiv=' name" do
            let(:response_body) do
              <<~HTML
                <html>
                  <head>
                    <meta http-equiv= "refresh" content="10;url='#{subject.test_url}'"/>
                  </head>
                  <body>
                    <p>example content</p>
                    <p>included content</p>
                    <p>more content</p>
                  </body>
                </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be_truthy
            end
          end

          context "when the http-equiv attribute is single quoted" do
            let(:response_body) do
              <<~HTML
                <html>
                  <head>
                    <meta http-equiv='refresh' content="10;url='#{subject.test_url}'"/>
                  </head>
                  <body>
                    <p>example content</p>
                    <p>included content</p>
                    <p>more content</p>
                  </body>
                </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be_truthy
            end
          end

          context "when the http-equiv attribute is not quoted" do
            let(:response_body) do
              <<~HTML
                <html>
                  <head>
                    <meta http-equiv=refresh content="10;url='#{subject.test_url}'"/>
                  </head>
                  <body>
                    <p>example content</p>
                    <p>included content</p>
                    <p>more content</p>
                  </body>
                </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be_truthy
            end
          end

          context "when the meta refresh has a delay value" do
            let(:response_body) do
              <<~HTML
                <html>
                  <head>
                    <meta http-equiv="refresh" content="10;url='#{subject.test_url}'"/>
                  </head>
                  <body>
                    <p>example content</p>
                    <p>included content</p>
                    <p>more content</p>
                  </body>
                </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be_truthy
            end
          end

          context "when there is a space between the delay value and the url value" do
            let(:response_body) do
              <<~HTML
                <html>
                  <head>
                    <meta http-equiv="refresh" content="10; url='#{subject.test_url}'"/>
                  </head>
                  <body>
                    <p>example content</p>
                    <p>included content</p>
                    <p>more content</p>
                  </body>
                </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be_truthy
            end
          end

          context "when there is a newline between the delay value and the url value" do
            let(:response_body) do
              <<~HTML
                              <html>
                                <head>
                                  <meta http-equiv="refresh" content="10;
                url='#{subject.test_url}'"/>
                                </head>
                                <body>
                                  <p>example content</p>
                                  <p>included content</p>
                                  <p>more content</p>
                                </body>
                              </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be_truthy
            end
          end

          context "when the url name is uppercase" do
            let(:response_body) do
              <<~HTML
                <html>
                  <head>
                    <meta http-equiv="refresh" content="0;URL='#{subject.test_url}'"/>
                  </head>
                  <body>
                    <p>example content</p>
                    <p>included content</p>
                    <p>more content</p>
                  </body>
                </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be_truthy
            end
          end

          context "when the http-equiv attribute is single quoted" do
            let(:response_body) do
              <<~HTML
                <html>
                  <head>
                    <meta http-equiv='refresh' content="0;url='#{subject.test_url}'"/>
                  </head>
                  <body>
                    <p>example content</p>
                    <p>included content</p>
                    <p>more content</p>
                  </body>
                </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be_truthy
            end
          end

          context "when the content attribute is single quoted" do
            context "and the url value is double quoted" do
              let(:response_body) do
                <<~HTML
                  <html>
                    <head>
                      <meta http-equiv="refresh" content='0;url="#{subject.test_url}"'/>
                    </head>
                    <body>
                      <p>example content</p>
                      <p>included content</p>
                      <p>more content</p>
                    </body>
                  </html>
                HTML
              end

              it "must return true" do
                expect(subject.vulnerable?).to be_truthy
              end
            end
          end

          context "when the content attribute is not quoted" do
            context "and the url value is double quoted" do
              let(:response_body) do
                <<~HTML
                  <html>
                    <head>
                      <meta http-equiv="refresh" content=0;url="#{subject.test_url}"/>
                    </head>
                    <body>
                      <p>example content</p>
                      <p>included content</p>
                      <p>more content</p>
                    </body>
                  </html>
                HTML
              end

              it "must return true" do
                expect(subject.vulnerable?).to be_truthy
              end
            end

            context "and the url value is single quoted" do
              let(:response_body) do
                <<~HTML
                  <html>
                    <head>
                      <meta http-equiv="refresh" content=0;url='#{subject.test_url}'/>
                    </head>
                    <body>
                      <p>example content</p>
                      <p>included content</p>
                      <p>more content</p>
                    </body>
                  </html>
                HTML
              end

              it "must return true" do
                expect(subject.vulnerable?).to be_truthy
              end
            end
          end

          context "when there is a space after the content attribute name" do
            let(:response_body) do
              <<~HTML
                <html>
                  <head>
                    <meta http-equiv="refresh" content ="0;url='#{subject.test_url}'"/>
                  </head>
                  <body>
                    <p>example content</p>
                    <p>included content</p>
                    <p>more content</p>
                  </body>
                </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be_truthy
            end
          end

          context "when there is a space after 'content='" do
            let(:response_body) do
              <<~HTML
                <html>
                  <head>
                    <meta http-equiv="refresh" content= "0;url='#{subject.test_url}'"/>
                  </head>
                  <body>
                    <p>example content</p>
                    <p>included content</p>
                    <p>more content</p>
                  </body>
                </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be_truthy
            end
          end

          context "when there is a space after the url name" do
            let(:response_body) do
              <<~HTML
                <html>
                  <head>
                    <meta http-equiv="refresh" content="0;url ='#{subject.test_url}'"/>
                  </head>
                  <body>
                    <p>example content</p>
                    <p>included content</p>
                    <p>more content</p>
                  </body>
                </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be_truthy
            end
          end

          context "when there is a space after 'url='" do
            let(:response_body) do
              <<~HTML
                <html>
                  <head>
                    <meta http-equiv="refresh" content= "0;url= '#{subject.test_url}'"/>
                  </head>
                  <body>
                    <p>example content</p>
                    <p>included content</p>
                    <p>more content</p>
                  </body>
                </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be_truthy
            end
          end

          context "when there is a space before the url value'" do
            let(:response_body) do
              <<~HTML
                <html>
                  <head>
                    <meta http-equiv="refresh" content= "0;url=' #{subject.test_url}'"/>
                  </head>
                  <body>
                    <p>example content</p>
                    <p>included content</p>
                    <p>more content</p>
                  </body>
                </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be_truthy
            end
          end

          context "when there is a space after the url value'" do
            let(:response_body) do
              <<~HTML
                <html>
                  <head>
                    <meta http-equiv="refresh" content= "0;url='#{subject.test_url} '"/>
                  </head>
                  <body>
                    <p>example content</p>
                    <p>included content</p>
                    <p>more content</p>
                  </body>
                </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be_truthy
            end
          end

          context "when there is a space at the end the content attribute's value'" do
            let(:response_body) do
              <<~HTML
                <html>
                  <head>
                    <meta http-equiv="refresh" content= "0;url='#{subject.test_url}' "/>
                  </head>
                  <body>
                    <p>example content</p>
                    <p>included content</p>
                    <p>more content</p>
                  </body>
                </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be_truthy
            end
          end

          context "when the meta tag ends with '/>'" do
            let(:response_body) do
              <<~HTML
                <html>
                  <head>
                    <meta http-equiv="refresh" content="0;url='#{subject.test_url}'"/>
                  </head>
                  <body>
                    <p>example content</p>
                    <p>included content</p>
                    <p>more content</p>
                  </body>
                </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be_truthy
            end

            context "when there is a space before the '/>'" do
              let(:response_body) do
                <<~HTML
                  <html>
                    <head>
                      <meta http-equiv="refresh" content="0;url='#{subject.test_url}'" />
                    </head>
                    <body>
                      <p>example content</p>
                      <p>included content</p>
                      <p>more content</p>
                    </body>
                  </html>
                HTML
              end

              it "must return true" do
                expect(subject.vulnerable?).to be_truthy
              end
            end
          end

          context "when the meta tag ends with '/ >'" do
            let(:response_body) do
              <<~HTML
                <html>
                  <head>
                    <meta http-equiv="refresh" content="0;url='#{subject.test_url}'"/ >
                  </head>
                  <body>
                    <p>example content</p>
                    <p>included content</p>
                    <p>more content</p>
                  </body>
                </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be_truthy
            end

            context "when there is a space before the '/ >'" do
              let(:response_body) do
                <<~HTML
                  <html>
                    <head>
                      <meta http-equiv="refresh" content="0;url='#{subject.test_url}'" / >
                    </head>
                    <body>
                      <p>example content</p>
                      <p>included content</p>
                      <p>more content</p>
                    </body>
                  </html>
                HTML
              end

              it "must return true" do
                expect(subject.vulnerable?).to be_truthy
              end
            end
          end

          context "when the meta tag ends with '>'" do
            let(:response_body) do
              <<~HTML
                <html>
                  <head>
                    <meta http-equiv="refresh" content="0;url='#{subject.test_url}'">
                  </head>
                  <body>
                    <p>example content</p>
                    <p>included content</p>
                    <p>more content</p>
                  </body>
                </html>
              HTML
            end

            it "must return true" do
              expect(subject.vulnerable?).to be_truthy
            end

            context "when there is a space before the '>'" do
              let(:response_body) do
                <<~HTML
                  <html>
                    <head>
                      <meta http-equiv="refresh" content="0;url='#{subject.test_url}'" >
                    </head>
                    <body>
                      <p>example content</p>
                      <p>included content</p>
                      <p>more content</p>
                    </body>
                  </html>
                HTML
              end

              it "must return true" do
                expect(subject.vulnerable?).to be_truthy
              end
            end
          end
        end
      end

      context "but the response Content-Type does not contain 'text/html'" do
        let(:content_type) { "text/plain" }
        let(:response) do
          double('Net::HTTPResponse', code:         code,
                                      content_type: content_type,
                                      body:         response_body)
        end

        it "must return false" do
          expect(subject.vulnerable?).to be_falsy
        end
      end
    end
  end
end
