require 'spec_helper'
require 'web_vuln_examples'
require 'ronin/vulns/web_vuln'

require 'webmock/rspec'

describe Ronin::Vulns::WebVuln do
  let(:query_param) { 'id' }
  let(:url) { "https://example.com/page?#{query_param}=1" }

  subject { described_class.new(url, query_param: query_param) }

  describe "#initialize" do
    include_examples "Ronin::Vulns::WebVuln#initialize examples"
  end

  let(:payload) { 'injection' }

  describe "#request" do
    let(:request_method) { :put }
    let(:user)           { 'bob' }
    let(:password)       { 'p@ssword' }

    let(:cookie_param)   { 'session_id' }
    let(:cookie_value)   { '1234'       }
    let(:cookie)         { {cookie_param => cookie_value} }

    let(:referer)        { 'https://example.com/' }

    let(:header_name1)  { 'X-Foo' }
    let(:header_value1) { 'foo'   }
    let(:header_name2)  { 'X-Bar' }
    let(:header_value2) { 'bar'   }
    let(:headers) do
      {
        'X-Foo' => 'foo',
        'X-Bar' => 'bar'
      }
    end

    let(:form_param1) { 'a'   }
    let(:form_value1) { 'foo' }
    let(:form_param2) { 'b'   }
    let(:form_value2) { 'bar' }
    let(:form_data) do
      {
        form_param1 => form_value1,
        form_param2 => form_value2
      }
    end

    subject do
      described_class.new(
        url,
        request_method: request_method,
        user:           user,
        password:       password,
        cookie:         cookie,
        referer:        referer,
        headers:        headers,
        form_data:      form_data
      )
    end

    it "must call #http.request with the #request_method, #url.path, #user, #password, #query_params, #cookie, #referer, #headers, #form_data" do
      stub_request(request_method, url).with(
        basic_auth: [user, password],
        headers: {
          'Accept'          => '*/*',
          'Accept-Encoding' => 'gzip;q=1.0,deflate;q=0.6,identity;q=0.3',
          'Content-Type'    => 'application/x-www-form-urlencoded',
          'Cookie'          => "#{cookie_param}=#{cookie_value}",
          'Referer'         => referer,
          'User-Agent'      => 'Ruby',
          header_name1      => header_value1,
          header_name2      => header_value2
        },
        body: form_data
      )

      subject.request
    end
  end

  describe "#exploit_query_params" do
    context "when #query_param is not set" do
      subject { described_class.new(url, header_name: 'X-Foo') }

      it "must return #query_params unmodified" do
        expect(subject.exploit_query_params(payload)).to be(subject.query_params)
      end
    end

    context "when #query_param is set" do
      let(:query_param) { 'id' }
      let(:url) { "https://example.com/page?#{query_param}=1&foo=bar" }

      subject { described_class.new(url, query_param: query_param) }

      context "when #query_params is set" do
        it "must return #query_params with #query_param overridden with the payload" do
          expect(subject.exploit_query_params(payload)).to eq(
            subject.query_params.merge(query_param => payload)
          )
        end
      end

      context "when #query_params is nil" do
        let(:url) { "https://example.com/page" }

        it "must return a new Hash containing #query_param and the payload" do
          expect(subject.exploit_query_params(payload)).to eq(
            {query_param => payload}
          )
        end
      end
    end
  end

  describe "#exploit_headers" do
    let(:headers) do
      {'X-Foo' => 'bar', 'X-Bar' => 'baz'}
    end

    context "when #header_name is not set" do
      context "when #headers is set" do
        subject do
          described_class.new(url, query_param: 'foo', headers: headers)
        end

        it "must return #headers unmodified" do
          expect(subject.exploit_headers(payload)).to be(subject.headers)
        end
      end

      context "when #headers is not set" do
        it "must return nil" do
          expect(subject.exploit_headers(payload)).to be(nil)
        end
      end
    end

    context "when #header_name is set" do
      let(:header_name) { 'X-Foo' }

      context "when #headers is set" do
        subject do
          described_class.new(url, header_name: header_name, headers: headers)
        end

        it "must return #headers with #header_name overridden with the payload" do
          expect(subject.exploit_headers(payload)).to eq(
            subject.headers.merge(header_name => payload)
          )
        end
      end

      context "when #headers is nil" do
        subject { described_class.new(url, header_name: header_name) }

        it "must return a new Hash containing #header_name and the payload" do
          expect(subject.exploit_headers(payload)).to eq(
            {header_name => payload}
          )
        end
      end
    end
  end

  describe "#exploit_cookie" do
    let(:cookie) do
      {'foo' => 'A', 'bar' => 'B', 'baz' => 'C'}
    end

    context "when #cookie_param is not set" do
      context "when #cookie is set" do
        subject do
          described_class.new(url, query_param: 'foo', cookie: cookie)
        end

        it "must return #cookie unmodified" do
          expect(subject.exploit_cookie(payload)).to be(subject.cookie)
        end
      end

      context "when #cookie is not set" do
        it "must return nil" do
          expect(subject.exploit_cookie(payload)).to be(nil)
        end
      end
    end

    context "when #cookie_param is set" do
      let(:cookie_param) { 'bar' }

      context "when #cookie is set" do
        subject do
          described_class.new(url, cookie_param: cookie_param,
                                   cookie:       cookie)
        end

        it "must return #cookie with #cookie_param overridden with the payload" do
          expect(subject.exploit_cookie(payload)).to eq(
            subject.cookie.merge(cookie_param => payload)
          )
        end
      end

      context "when #cookie is nil" do
        subject { described_class.new(url, cookie_param: cookie_param) }

        it "must return a new Hash containing #cookie_param and the payload" do
          expect(subject.exploit_cookie(payload)).to eq(
            {cookie_param => payload}
          )
        end
      end
    end
  end

  describe "#exploit_form_data" do
    let(:form_data) do
      {'foo' => 'A', 'bar' => 'B', 'baz' => 'C'}
    end

    context "when #form_param is not set" do
      context "when #form_data is set" do
        subject do
          described_class.new(url, query_param: 'foo', form_data: form_data)
        end

        it "must return #form_data unmodified" do
          expect(subject.exploit_form_data(payload)).to be(subject.form_data)
        end
      end

      context "when #form_data is not set" do
        it "must return nil" do
          expect(subject.exploit_form_data(payload)).to be(nil)
        end
      end
    end

    context "when #form_param is set" do
      let(:form_param) { 'bar' }

      context "when #form_data is set" do
        subject do
          described_class.new(url, form_param: form_param,
                                   form_data:       form_data)
        end

        it "must return #form_data with #form_param overridden with the payload" do
          expect(subject.exploit_form_data(payload)).to eq(
            subject.form_data.merge(form_param => payload)
          )
        end
      end

      context "when #form_data is nil" do
        subject { described_class.new(url, form_param: form_param) }

        it "must return a new Hash containing #form_param and the payload" do
          expect(subject.exploit_form_data(payload)).to eq(
            {form_param => payload}
          )
        end
      end
    end
  end

  describe "#encode_payload" do
    let(:payload) { 'test payload' }

    it "must return the payload" do
      expect(subject.encode_payload(payload)).to eq(payload)
    end

    context "when given a non-String object" do
      let(:payload) { 42 }

      it "must convert it to a String" do
        expect(subject.encode_payload(payload)).to eq(payload.to_s)
      end
    end
  end

  describe "#exploit" do
    let(:payload)         { 'test'  }
    let(:encoded_payload) { payload }

    include_examples "Ronin::Vulns::WebVuln#exploit examples"
  end

  class TestWebVuln < Ronin::Vulns::WebVuln

    def vulnerable?
      response = exploit('injection')
      body     = response.body

      return body.include?('injection')
    end

  end

  describe ".scan_query_params" do
    let(:base_url) { "https://example.com/page"      }
    let(:url)      { "#{base_url}?foo=1&bar=2&baz=3" }
    let(:payload)  { 'injection' }

    subject { TestWebVuln }

    context "when query_params is not given" do
      it "must send requests with each query param containing the payload" do
        stub_request(:get, "#{base_url}?foo=#{payload}&bar=2&baz=3")
        stub_request(:get, "#{base_url}?foo=1&bar=#{payload}&baz=3")
        stub_request(:get, "#{base_url}?foo=1&bar=2&baz=#{payload}")

        subject.scan_query_params(url)
      end
    end

    context "when query_params is given" do
      let(:query_params) { %w[foo baz] }

      it "must send requests with only those query params containing the payload" do
        stub_request(:get, "#{base_url}?foo=#{payload}&bar=2&baz=3")
        stub_request(:get, "#{base_url}?foo=1&bar=2&baz=#{payload}")

        subject.scan_query_params(url,query_params)
      end
    end

    context "when one of the responses indicates it's vulnerable" do
      it "must return those vulnerable instances" do
        stub_request(:get, "#{base_url}?foo=#{payload}&bar=2&baz=3").to_return(body: "<html>#{payload}</html>")
        stub_request(:get, "#{base_url}?foo=1&bar=#{payload}&baz=3")
        stub_request(:get, "#{base_url}?foo=1&bar=2&baz=#{payload}").to_return(body: "<html>#{payload}</html>")

        vulns = subject.scan_query_params(url)

        expect(vulns.length).to eq(2)
        expect(vulns).to all(be_kind_of(subject))
        expect(vulns[0].query_param).to eq('foo')
        expect(vulns[1].query_param).to eq('baz')
      end

      context "and when a block is given" do
        it "must yield each vulnerable instance" do
          stub_request(:get, "#{base_url}?foo=#{payload}&bar=2&baz=3").to_return(body: "<html>#{payload}</html>")
          stub_request(:get, "#{base_url}?foo=1&bar=#{payload}&baz=3")
          stub_request(:get, "#{base_url}?foo=1&bar=2&baz=#{payload}").to_return(body: "<html>#{payload}</html>")

          yielded_vulns = []

          subject.scan_query_params(url) do |vuln|
            yielded_vulns << vuln
          end

          expect(yielded_vulns.length).to eq(2)
          expect(yielded_vulns).to all(be_kind_of(subject))
          expect(yielded_vulns[0].query_param).to eq('foo')
          expect(yielded_vulns[1].query_param).to eq('baz')
        end
      end
    end
  end

  describe ".scan_headers" do
    let(:url)          { "https://example.com/page" }
    let(:header_names) { %w[X-Foo X-Bar X-Baz] }
    let(:payload)      { 'injection' }

    subject { TestWebVuln }

    it "must send requests with each header name containing the payload" do
      stub_request(:get, url).with(headers: {header_names[0] => payload})
      stub_request(:get, url).with(headers: {header_names[1] => payload})
      stub_request(:get, url).with(headers: {header_names[2] => payload})

      subject.scan_headers(url,header_names)
    end

    context "when one of the responses indicates it's vulnerable" do
      it "must return those vulnerable instances" do
        stub_request(:get, url).with(headers: {header_names[0] => payload}).to_return(body: "<html>#{payload}</html>")
        stub_request(:get, url).with(headers: {header_names[1] => payload})
        stub_request(:get, url).with(headers: {header_names[2] => payload}).to_return(body: "<html>#{payload}</html>")

        vulns = subject.scan_headers(url,header_names)

        expect(vulns.length).to eq(2)
        expect(vulns).to all(be_kind_of(subject))
        expect(vulns[0].header_name).to eq(header_names[0])
        expect(vulns[1].header_name).to eq(header_names[2])
      end

      context "and when a block is given" do
        it "must yield each vulnerable instance" do
          stub_request(:get, url).with(headers: {header_names[0] => payload}).to_return(body: "<html>#{payload}</html>")
          stub_request(:get, url).with(headers: {header_names[1] => payload})
          stub_request(:get, url).with(headers: {header_names[2] => payload}).to_return(body: "<html>#{payload}</html>")

          yielded_vulns = []

          subject.scan_headers(url,header_names) do |vuln|
            yielded_vulns << vuln
          end

          expect(yielded_vulns.length).to eq(2)
          expect(yielded_vulns).to all(be_kind_of(subject))
          expect(yielded_vulns[0].header_name).to eq(header_names[0])
          expect(yielded_vulns[1].header_name).to eq(header_names[2])
        end
      end
    end
  end

  describe ".scan_cookie_params" do
    let(:url)           { "https://example.com/page" }
    let(:cookie_params) { %w[foo bar baz] }
    let(:payload)       { 'injection' }

    subject { TestWebVuln }

    context "when no cookie_params to scan are given" do
      it "must first request the URL and scan the params in the Set-Cookie header" do
        stub_request(:get, url).to_return(headers: {'Set-Cookie' => "#{cookie_params[0]}=1; #{cookie_params[1]}=2; #{cookie_params[2]}=3; Path=/"})
        stub_request(:get, url).with(headers: {'Cookie' => "foo=#{payload}; bar=2; baz=3"})
        stub_request(:get, url).with(headers: {'Cookie' => "foo=1; bar=#{payload}; baz=3"})
        stub_request(:get, url).with(headers: {'Cookie' => "foo=1; bar=2; baz=#{payload}"})

        subject.scan_cookie_params(url)
      end
    end

    context "when the cookie_params to scan are given" do
      it "must send requests with each Cookie param set to the payload" do
        stub_request(:get, url).with(headers: {'Cookie' => "foo=#{payload}"})
        stub_request(:get, url).with(headers: {'Cookie' => "bar=#{payload}"})
        stub_request(:get, url).with(headers: {'Cookie' => "baz=#{payload}"})

        subject.scan_cookie_params(url,cookie_params)
      end

      context "and a cookie: value is given" do
        let(:cookie) do
          {
            cookie_params[0] => '1',
            cookie_params[1] => '2',
            cookie_params[2] => '3'
          }
        end

        it "must send requests with each Cookie param overridden with the payload" do
          stub_request(:get, url).with(headers: {'Cookie' => "foo=#{payload}; bar=2; baz=3"})
          stub_request(:get, url).with(headers: {'Cookie' => "foo=1; bar=#{payload}; baz=3"})
          stub_request(:get, url).with(headers: {'Cookie' => "foo=1; bar=2; baz=#{payload}"})

          subject.scan_cookie_params(url,cookie_params, cookie: cookie)
        end
      end
    end

    context "when one of the responses indicates it's vulnerable" do
      it "must return those vulnerable instances" do
        stub_request(:get, url).with(headers: {'Cookie' => "#{cookie_params[0]}=#{payload}"}).to_return(body: "<html>#{payload}</html>")
        stub_request(:get, url).with(headers: {'Cookie' => "#{cookie_params[1]}=#{payload}"})
        stub_request(:get, url).with(headers: {'Cookie' => "#{cookie_params[2]}=#{payload}"}).to_return(body: "<html>#{payload}</html>")

        vulns = subject.scan_cookie_params(url,cookie_params)

        expect(vulns.length).to eq(2)
        expect(vulns).to all(be_kind_of(subject))
        expect(vulns[0].cookie_param).to eq(cookie_params[0])
        expect(vulns[1].cookie_param).to eq(cookie_params[2])
      end

      context "and when a block is given" do
        it "must yield each vulnerable instance" do
          stub_request(:get, url).with(headers: {'Cookie' => "#{cookie_params[0]}=#{payload}"}).to_return(body: "<html>#{payload}</html>")
          stub_request(:get, url).with(headers: {'Cookie' => "#{cookie_params[1]}=#{payload}"})
          stub_request(:get, url).with(headers: {'Cookie' => "#{cookie_params[2]}=#{payload}"}).to_return(body: "<html>#{payload}</html>")

          yielded_vulns = []

          subject.scan_cookie_params(url,cookie_params) do |vuln|
            yielded_vulns << vuln
          end

          expect(yielded_vulns.length).to eq(2)
          expect(yielded_vulns).to all(be_kind_of(subject))
          expect(yielded_vulns[0].cookie_param).to eq(cookie_params[0])
          expect(yielded_vulns[1].cookie_param).to eq(cookie_params[2])
        end
      end
    end
  end

  describe ".scan_form_params" do
    let(:url)           { "https://example.com/page" }
    let(:form_params)   { %w[foo bar baz] }
    let(:payload)       { 'injection' }

    subject { TestWebVuln }

    it "must send requests with each Cookie param set to the payload" do
      stub_request(:get, url).with(body: "foo=#{payload}")
      stub_request(:get, url).with(body: "bar=#{payload}")
      stub_request(:get, url).with(body: "baz=#{payload}")

      subject.scan_form_params(url,form_params)
    end

    context "when a form_data: value is given" do
      let(:form_data) do
        {
          form_params[0] => '1',
          form_params[1] => '2',
          form_params[2] => '3'
        }
      end

      it "must send requests with each Cookie param overridden with the payload" do
        stub_request(:get, url).with(body: "foo=#{payload}&bar=2&baz=3")
        stub_request(:get, url).with(body: "foo=1&bar=#{payload}&baz=3")
        stub_request(:get, url).with(body: "foo=1&bar=2&baz=#{payload}")

        subject.scan_form_params(url,form_params, form_data: form_data)
      end

      context "and a form_params value is not given" do
        let(:form_params) { nil }
        let(:form_data) do
          {
            'foo' => '1',
            'bar' => '2',
            'baz' => '3'
          }
        end

        it "must send requests with each Cookie param overridden with the payload" do
          stub_request(:get, url).with(body: "foo=#{payload}&bar=2&baz=3")
          stub_request(:get, url).with(body: "foo=1&bar=#{payload}&baz=3")
          stub_request(:get, url).with(body: "foo=1&bar=2&baz=#{payload}")

          subject.scan_form_params(url,form_params, form_data: form_data)
        end
      end
    end

    context "when one of the responses indicates it's vulnerable" do
      it "must return those vulnerable instances" do
        stub_request(:get, url).with(body: "#{form_params[0]}=#{payload}").to_return(body: "<html>#{payload}</html>")
        stub_request(:get, url).with(body: "#{form_params[1]}=#{payload}")
        stub_request(:get, url).with(body: "#{form_params[2]}=#{payload}").to_return(body: "<html>#{payload}</html>")

        vulns = subject.scan_form_params(url,form_params)

        expect(vulns.length).to eq(2)
        expect(vulns).to all(be_kind_of(subject))
        expect(vulns[0].form_param).to eq(form_params[0])
        expect(vulns[1].form_param).to eq(form_params[2])
      end

      context "and when a block is given" do
        it "must yield each vulnerable instance" do
          stub_request(:get, url).with(body: "#{form_params[0]}=#{payload}").to_return(body: "<html>#{payload}</html>")
          stub_request(:get, url).with(body: "#{form_params[1]}=#{payload}")
          stub_request(:get, url).with(body: "#{form_params[2]}=#{payload}").to_return(body: "<html>#{payload}</html>")

          yielded_vulns = []

          subject.scan_form_params(url,form_params) do |vuln|
            yielded_vulns << vuln
          end

          expect(yielded_vulns.length).to eq(2)
          expect(yielded_vulns).to all(be_kind_of(subject))
          expect(yielded_vulns[0].form_param).to eq(form_params[0])
          expect(yielded_vulns[1].form_param).to eq(form_params[2])
        end
      end
    end
  end

  describe ".scan" do
    let(:url)     { "https://example.com/page?id=1" }
    let(:payload) { 'injection' }

    subject { TestWebVuln }

    context "when no keyword arguments are given" do
      let(:base_url) { "https://example.com/page"      }
      let(:url)      { "#{base_url}?foo=1&bar=2&baz=3" }

      it "must send requests with each query param containing the payload" do
        stub_request(:get, "#{base_url}?foo=#{payload}&bar=2&baz=3")
        stub_request(:get, "#{base_url}?foo=1&bar=#{payload}&baz=3")
        stub_request(:get, "#{base_url}?foo=1&bar=2&baz=#{payload}")

        subject.scan(url)
      end
    end

    context "when the query_params: keyword argument is given" do
      let(:base_url) { "https://example.com/page"      }
      let(:url)      { "#{base_url}?foo=1&bar=2&baz=3" }

      context "and it's true" do
        it "must send requests with each query param containing the payload" do
          stub_request(:get, "#{base_url}?foo=#{payload}&bar=2&baz=3")
          stub_request(:get, "#{base_url}?foo=1&bar=#{payload}&baz=3")
          stub_request(:get, "#{base_url}?foo=1&bar=2&baz=#{payload}")

          subject.scan(url)
        end
      end

      context "and it's an Array" do
        let(:query_params) { %w[foo baz] }

        it "must send requests with only those query params containing the payload" do
          stub_request(:get, "#{base_url}?foo=#{payload}&bar=2&baz=3")
          stub_request(:get, "#{base_url}?foo=1&bar=2&baz=#{payload}")

          subject.scan(url, query_params: query_params)
        end
      end
    end

    context "when the header_names: keyword argument is given" do
      let(:header_names) { %w[X-Foo X-Bar X-Baz] }

      it "must send requests with each header name containing the payload" do
        stub_request(:get, url).with(headers: {header_names[0] => payload})
        stub_request(:get, url).with(headers: {header_names[1] => payload})
        stub_request(:get, url).with(headers: {header_names[2] => payload})

        subject.scan(url, header_names: header_names)
      end
    end

    context "when the cookie_params: keyword argument is given" do
      let(:cookie_params) { %w[foo bar baz] }

      context "and it's true" do
        it "must first request the URL and scan the params in the Set-Cookie header" do
          stub_request(:get, url).to_return(headers: {'Set-Cookie' => "#{cookie_params[0]}=1; #{cookie_params[1]}=2; #{cookie_params[2]}=3; Path=/"})
          stub_request(:get, url).with(headers: {'Cookie' => "foo=#{payload}; bar=2; baz=3"})
          stub_request(:get, url).with(headers: {'Cookie' => "foo=1; bar=#{payload}; baz=3"})
          stub_request(:get, url).with(headers: {'Cookie' => "foo=1; bar=2; baz=#{payload}"})

          subject.scan(url, cookie_params: true)
        end
      end

      context "and it's an Array" do
        it "must send requests with each Cookie param set to the payload" do
          stub_request(:get, url).with(headers: {'Cookie' => "foo=#{payload}"})
          stub_request(:get, url).with(headers: {'Cookie' => "bar=#{payload}"})
          stub_request(:get, url).with(headers: {'Cookie' => "baz=#{payload}"})

          subject.scan(url, cookie_params: cookie_params)
        end

        context "and a cookie: value is given" do
          let(:cookie) do
            {
              cookie_params[0] => '1',
              cookie_params[1] => '2',
              cookie_params[2] => '3'
            }
          end

          it "must send requests with each Cookie param overridden with the payload" do
            stub_request(:get, url).with(headers: {'Cookie' => "foo=#{payload}; bar=2; baz=3"})
            stub_request(:get, url).with(headers: {'Cookie' => "foo=1; bar=#{payload}; baz=3"})
            stub_request(:get, url).with(headers: {'Cookie' => "foo=1; bar=2; baz=#{payload}"})

            subject.scan(url, cookie_params: cookie_params, cookie: cookie)
          end
        end
      end
    end

    context "when the form_params: keyword argument is given" do
      let(:form_params) { %w[foo bar baz] }

      it "must send requests with each Cookie param set to the payload" do
        stub_request(:get, url).with(body: "foo=#{payload}")
        stub_request(:get, url).with(body: "bar=#{payload}")
        stub_request(:get, url).with(body: "baz=#{payload}")

        subject.scan(url, form_params: form_params)
      end

      context "when a form_data: value is given" do
        let(:form_data) do
          {
            form_params[0] => '1',
            form_params[1] => '2',
            form_params[2] => '3'
          }
        end

        it "must send requests with each Cookie param overridden with the payload" do
          stub_request(:get, url).with(body: "foo=#{payload}&bar=2&baz=3")
          stub_request(:get, url).with(body: "foo=1&bar=#{payload}&baz=3")
          stub_request(:get, url).with(body: "foo=1&bar=2&baz=#{payload}")

          subject.scan(url, form_params: form_params, form_data: form_data)
        end
      end

      context "and it's true" do
        context "and a form_data: value is given" do
          let(:form_params) { nil }
          let(:form_data) do
            {
              'foo' => '1',
              'bar' => '2',
              'baz' => '3'
            }
          end

          it "must send requests with each Cookie param overridden with the payload" do
            stub_request(:get, url).with(body: "foo=#{payload}&bar=2&baz=3")
            stub_request(:get, url).with(body: "foo=1&bar=#{payload}&baz=3")
            stub_request(:get, url).with(body: "foo=1&bar=2&baz=#{payload}")

            subject.scan(url, form_params: true, form_data: form_data)
          end
        end
      end
    end
  end

  describe ".test" do
    subject { TestWebVuln }

    let(:vuln1) { subject.new(url, query_param: 'foo') }
    let(:vuln2) { subject.new(url, query_param: 'bar') }
    let(:vuln3) { subject.new(url, query_param: 'baz') }

    it "must call .scan and return the first vulnerable instance" do
      expect(subject).to receive(:scan).with(url).and_yield(vuln2).and_yield(vuln3)

      expect(subject.test(url)).to eq(vuln2)
    end

    context "when .scan does not yield any vulnerabiltieis" do
      it "must return nil" do
        expect(subject).to receive(:scan).with(url)

        expect(subject.test(url)).to be(nil)
      end
    end
  end

  describe "#original_value" do
    context "when #query_param is set" do
      let(:query_param) { 'bar' }
      let(:query_params) do
        {'foo' => 'a', query_param => 'b', 'baz' => '3'}
      end

      let(:url) do
        URI(super()).tap do |new_url|
          new_url.query_params = query_params
        end
      end

      subject do
        described_class.new(url, query_param: query_param)
      end

      it "must return the #query_param from #query_params" do
        expect(subject.original_value).to eq(query_params[query_param])
      end
    end

    context "when #header_name is set" do
      let(:header_name) { 'X-Bar' }

      context "when #headers is set" do
        let(:headers) do
          {'X-Foo' => 'a', header_name => 'b', 'X-Baz' => 'c'}
        end

        subject do
          described_class.new(url, header_name: header_name, headers: headers)
        end

        it "must return the #header_name from #headers" do
          expect(subject.original_value).to eq(headers[header_name])
        end
      end

      context "but #headers is not set" do
        subject do
          described_class.new(url, header_name: header_name)
        end

        it "must return nil" do
          expect(subject.original_value).to be(nil)
        end
      end
    end

    context "when #cookie_param is set" do
      let(:cookie_param) { 'bar' }

      context "when #cookie is set" do
        let(:cookie) do
          {'foo' => 'a', cookie_param => 'b', 'baz' => 'c'}
        end

        subject do
          described_class.new(url, cookie_param: cookie_param, cookie: cookie)
        end

        it "must return the #cookie_param from #cookie" do
          expect(subject.original_value).to eq(cookie[cookie_param])
        end
      end

      context "but #cookie is not set" do
        subject do
          described_class.new(url, cookie_param: cookie_param)
        end

        it "must return nil" do
          expect(subject.original_value).to be(nil)
        end
      end
    end

    context "when #form_param is set" do
      let(:form_param) { 'bar' }

      context "when #form_data is set" do
        let(:form_data) do
          {'foo' => 'a', form_param => 'b', 'baz' => 'c'}
        end

        subject do
          described_class.new(url, form_param: form_param, form_data: form_data)
        end

        it "must return the #form_param from #form_data" do
          expect(subject.original_value).to eq(form_data[form_param])
        end
      end

      context "but #form_data is not set" do
        subject do
          described_class.new(url, form_param: form_param)
        end

        it "must return nil" do
          expect(subject.original_value).to be(nil)
        end
      end
    end
  end

  describe "#random_value" do
    it "must return a random four character alphabetic value" do
      expect(subject.random_value).to match(/\A[A-Za-z]{4}\z/)
    end

    it "must return a random String each time" do
      strings = Array.new(3) { subject.random_value }

      expect(strings.uniq.length).to be > 1
    end
  end

  describe "#vulnerable?" do
    it do
      expect {
        subject.vulnerable?
      }.to raise_error(NotImplementedError,"#{subject.inspect} did not implement #vulnerable?")
    end
  end

  describe "#to_s" do
    it "must return the String version of #url" do
      expect(subject.to_s).to eq(url.to_s)
    end
  end

  describe "#to_curl" do
    context "when #request_method is not :get" do
      let(:request_method) { :put }

      subject { described_class.new(url, request_method: request_method) }

      it "must include the `--request` option with the #request_method" do
        expect(subject.to_curl).to eq(
          "curl --request #{request_method.upcase} '#{url}'"
        )
      end
    end

    context "when #user is set" do
      let(:user) { 'bob' }

      subject { described_class.new(url, user: user) }

      it "must include the '--user' option with the #user" do
        expect(subject.to_curl).to eq(
          "curl --user '#{user}:' '#{url}'"
        )
      end
    end

    context "when #password is set" do
      let(:password) { 'secret' }

      subject { described_class.new(url, password: password) }

      it "must include the '--user' option with the #password" do
        expect(subject.to_curl).to eq(
          "curl --user ':#{password}' '#{url}'"
        )
      end
    end

    context "when #user and #password are set" do
      let(:user)     { 'bob'    }
      let(:password) { 'secret' }

      subject { described_class.new(url, user: user, password: password) }

      it "must include the '--user' option with the #user and #password" do
        expect(subject.to_curl).to eq(
          "curl --user '#{user}:#{password}' '#{url}'"
        )
      end
    end

    context "when #referer is set" do
      let(:referer ) { 'https://example..com/' }

      subject { described_class.new(url, referer: referer) }

      it "must include the '--referer' option with the #referer" do
        expect(subject.to_curl).to eq(
          "curl --referer '#{referer}' '#{url}'"
        )
      end
    end

    context "when #query_param is set" do
      let(:url) { "https://example.com/page.php?id=1&foo=bar" }

      it "must return a curl command with PAYLOAD injected into the query params" do
        expect(subject.to_curl).to eq(
          "curl '#{subject.url.scheme}://#{subject.url.host}#{subject.url.path}?#{query_param}=PAYLOAD&foo=bar'"
        )
      end

      context "when a payload is given" do
        let(:payload) { 'test payload' }

        it "must use the custom payload" do
          expect(subject.to_curl(payload)).to eq(
            "curl '#{subject.url.scheme}://#{subject.url.host}#{subject.url.path}?#{query_param}=test%20payload&foo=bar'"
          )
        end
      end
    end

    context "when #header_name is set" do
      let(:header_name) { 'X-Foo' }
      let(:headers) do
        {'X-Foo' => 'bar', 'X-Bar' => 'baz'}
      end

      subject do
        described_class.new(url, header_name: header_name, headers: headers)
      end

      it "must return a curl command with the PAYLOAD injected into a `--header` option" do
        expect(subject.to_curl).to eq(
          "curl --header '#{header_name}: PAYLOAD' --header '#{headers.keys[1]}: #{headers.values[1]}' '#{url}'"
        )
      end

      context "when a payload is given" do
        let(:payload) { 'test payload' }

        it "must use the custom payload" do
          expect(subject.to_curl(payload)).to eq(
            "curl --header '#{header_name}: #{payload}' --header '#{headers.keys[1]}: #{headers.values[1]}' '#{url}'"
          )
        end
      end
    end

    context "when #cookie_param is set" do
      let(:cookie_param) { 'bar' }
      let(:cookie) do
        {'foo' => 'A', 'bar' => 'B', 'baz' => 'C'}
      end

      subject do
        described_class.new(url, cookie_param: cookie_param,
                                 cookie:       cookie)
      end

      it "must return a curl command with the PAYLOAD injected into a `--cookie` option" do
        expect(subject.to_curl).to eq(
          "curl --cookie '#{cookie.keys[0]}=#{cookie.values[0]}; #{cookie_param}=PAYLOAD; #{cookie.keys[2]}=#{cookie.values[2]}' '#{url}'"
        )
      end

      context "when a payload is given" do
        let(:payload)         { 'test payload' }
        let(:encoded_payload) { 'test+payload' }

        it "must use the custom payload" do
          expect(subject.to_curl(payload)).to eq(
            "curl --cookie '#{cookie.keys[0]}=#{cookie.values[0]}; #{cookie_param}=#{encoded_payload}; #{cookie.keys[2]}=#{cookie.values[2]}' '#{url}'"
          )
        end
      end
    end

    context "when #form_param is set" do
      let(:form_data) do
        {'foo' => 'A', 'bar' => 'B', 'baz' => 'C'}
      end
      let(:form_param) { 'bar' }

      subject do
        described_class.new(url, form_param: form_param,
                                 form_data:       form_data)
      end

      it "must return a curl command with the PAYLOAD injected into a `--form-string` option" do
        expect(subject.to_curl).to eq(
          "curl --form-string '#{form_data.keys[0]}=#{form_data.values[0]}&#{form_param}=PAYLOAD&#{form_data.keys[2]}=#{form_data.values[2]}' '#{url}'"
        )
      end

      context "when a payload is given" do
        let(:payload)         { 'test payload' }
        let(:encoded_payload) { 'test+payload' }

        it "must use the custom payload" do
          expect(subject.to_curl(payload)).to eq(
            "curl --form-string '#{form_data.keys[0]}=#{form_data.values[0]}&#{form_param}=#{encoded_payload}&#{form_data.keys[2]}=#{form_data.values[2]}' '#{url}'"
          )
        end
      end
    end
  end

  describe "#to_http" do
    it "must return \"GET /path?query_params... HTTP/1.1\" in the command" do
      expect(subject.to_http).to eq(
        "GET #{subject.url.path}?#{query_param}=PAYLOAD HTTP/1.1\r\n"
      )
    end

    context "when #request_method is not :get" do
      let(:request_method) { :put }

      subject { described_class.new(url, request_method: request_method) }

      it "must use the #request_method in the HTTP response" do
        expect(subject.to_http).to eq(
          "#{request_method.upcase} #{subject.url.request_uri} HTTP/1.1\r\n"
        )
      end
    end

    context "when #user is set" do
      let(:user) { 'bob' }

      subject { described_class.new(url, user: user) }

      it "must include the 'Authorization: Basic ...' header" do
        basic_auth = ["#{user}:"].pack('m0')

        expect(subject.to_http).to eq(
          [
            "GET #{subject.url.request_uri} HTTP/1.1",
            "Authorization: Basic #{basic_auth}",
            ''
          ].join("\r\n")
        )
      end
    end

    context "when #password is set" do
      let(:password) { 'secret' }

      subject { described_class.new(url, password: password) }

      it "must include the 'Authorization: Basic ...' header" do
        basic_auth = [":#{password}"].pack('m0')

        expect(subject.to_http).to eq(
          [
            "GET #{subject.url.request_uri} HTTP/1.1",
            "Authorization: Basic #{basic_auth}",
            ''
          ].join("\r\n")
        )
      end
    end

    context "when #user and #password are set" do
      let(:user)     { 'bob'    }
      let(:password) { 'secret' }

      subject { described_class.new(url, user: user, password: password) }

      it "must include the 'Authorization: Basic ...' header" do
        basic_auth = ["#{user}:#{password}"].pack('m0')

        expect(subject.to_http).to eq(
          [
            "GET #{subject.url.request_uri} HTTP/1.1",
            "Authorization: Basic #{basic_auth}",
            ''
          ].join("\r\n")
        )
      end
    end

    context "when #referer is set" do
      let(:referer ) { 'https://example..com/' }

      subject { described_class.new(url, referer: referer) }

      it "must include the 'Referer: ...' header" do
        expect(subject.to_http).to eq(
          [
            "GET #{subject.url.request_uri} HTTP/1.1",
            "Referer: #{referer}",
            ''
          ].join("\r\n")
        )
      end
    end

    context "when #query_param is set" do
      let(:url) { "https://example.com/page.php?id=1&foo=bar" }

      it "must return a HTTP request with PAYLOAD injected into the query params" do
        expect(subject.to_http).to eq(
          "GET #{subject.url.path}?#{query_param}=PAYLOAD&foo=bar HTTP/1.1\r\n"
        )
      end

      context "when a payload is given" do
        let(:payload) { 'test payload' }

        it "must use the custom payload" do
          expect(subject.to_http(payload)).to eq(
            "GET #{subject.url.path}?#{query_param}=test%20payload&foo=bar HTTP/1.1\r\n"
          )
        end
      end
    end

    context "when #header_name is set" do
      let(:header_name) { 'X-Foo' }
      let(:headers) do
        {'X-Foo' => 'bar', 'X-Bar' => 'baz'}
      end

      subject do
        described_class.new(url, header_name: header_name, headers: headers)
      end

      it "must return a HTTP request with the PAYLOAD injected into the headers" do
        expect(subject.to_http).to eq(
          [
            "GET #{subject.url.request_uri} HTTP/1.1",
            "#{header_name}: PAYLOAD",
            "#{headers.keys[1]}: #{headers.values[1]}",
            ''
          ].join("\r\n")
        )
      end

      context "when a payload is given" do
        let(:payload) { 'test payload' }

        it "must use the custom payload" do
          expect(subject.to_http(payload)).to eq(
            [
              "GET #{subject.url.request_uri} HTTP/1.1",
              "#{header_name}: #{payload}",
              "#{headers.keys[1]}: #{headers.values[1]}",
              ''
            ].join("\r\n")
          )
        end
      end
    end

    context "when #cookie_param is set" do
      let(:cookie_param) { 'bar' }
      let(:cookie) do
        {'foo' => 'A', 'bar' => 'B', 'baz' => 'C'}
      end

      subject do
        described_class.new(url, cookie_param: cookie_param,
                                 cookie:       cookie)
      end

      it "must return a HTTP request with the PAYLOAD injected into a 'Cookie' header" do
        expect(subject.to_http).to eq(
          [
            "GET #{subject.url.request_uri} HTTP/1.1",
            "Cookie: #{cookie.keys[0]}=#{cookie.values[0]}; #{cookie_param}=PAYLOAD; #{cookie.keys[2]}=#{cookie.values[2]}",
            ''
          ].join("\r\n")
        )
      end

      context "when a payload is given" do
        let(:payload)         { 'test payload' }
        let(:encoded_payload) { 'test+payload' }

        it "must use the custom payload" do
          expect(subject.to_http(payload)).to eq(
            [
              "GET #{subject.url.request_uri} HTTP/1.1",
              "Cookie: #{cookie.keys[0]}=#{cookie.values[0]}; #{cookie_param}=#{encoded_payload}; #{cookie.keys[2]}=#{cookie.values[2]}",
              ''
            ].join("\r\n")
          )
        end
      end
    end

    context "when #form_param is set" do
      let(:form_data) do
        {'foo' => 'A', 'bar' => 'B', 'baz' => 'C'}
      end
      let(:form_param) { 'bar' }

      subject do
        described_class.new(url, form_param: form_param,
                                 form_data:       form_data)
      end

      it "must return a HTTP request with the PAYLOAD injected into the form body" do
        expect(subject.to_http).to eq(
          [
            "GET #{subject.url.request_uri} HTTP/1.1",
            'Content-Type: x-www-form-urlencoded',
            '',
            "#{form_data.keys[0]}=#{form_data.values[0]}&#{form_param}=PAYLOAD&#{form_data.keys[2]}=#{form_data.values[2]}",
            ''
          ].join("\r\n")
        )
      end

      context "when a payload is given" do
        let(:payload)         { 'test payload' }
        let(:encoded_payload) { 'test+payload' }

        it "must use the custom payload" do
          expect(subject.to_http(payload)).to eq(
            [
              "GET #{subject.url.request_uri} HTTP/1.1",
              'Content-Type: x-www-form-urlencoded',
              '',
              "#{form_data.keys[0]}=#{form_data.values[0]}&#{form_param}=#{encoded_payload}&#{form_data.keys[2]}=#{form_data.values[2]}",
              ''
            ].join("\r\n")
          )
        end
      end
    end
  end
end
