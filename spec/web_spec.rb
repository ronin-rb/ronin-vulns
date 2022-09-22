require 'spec_helper'
require 'web_vuln_examples'
require 'ronin/vulns/web'

require 'webmock/rspec'

describe Ronin::Vulns::Web do
  let(:query_param)  { 'id' }
  let(:url) { "https://example.com/page?#{query_param}=1" }

  subject { described_class.new(url, query_param: query_param) }

  describe "#initialize" do
    include_examples "Ronin::Vulns::Web#initialize examples"
  end

  let(:payload) { 'injection' }

  describe "#exploit_query_params" do
    context "when #query_param is not set" do
      subject { described_class.new(url, header_name: 'X-Foo') }

      it "must return #query_params unmodified" do
        expect(subject.exploit_query_params(payload)).to be(subject.query_params)
      end
    end

    context "when #query_param is set" do
      let(:query_param)  { 'id' }
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
      let(:header_name)  { 'X-Foo' }

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
      let(:cookie_param)  { 'bar' }

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
      let(:form_param)  { 'bar' }

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

  describe "#exploit" do
    include_examples "Ronin::Vulns::Web#exploit examples"
  end

  class TestWebVuln < Ronin::Vulns::Web

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
      let(:form_params)   { %w[foo bar baz] }

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
end
