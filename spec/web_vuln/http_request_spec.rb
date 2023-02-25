require 'spec_helper'
require 'ronin/vulns/web_vuln/http_request'

describe Ronin::Vulns::WebVuln::HTTPRequest do
  let(:url) { URI.parse('https://example.com/page.php?id=1') }

  let(:request_method) { :post }
  let(:user)           { 'bob' }
  let(:password)       { 'secret' }
  let(:referer)        { 'https://example.com/' }
  let(:query_params)   { {'id' => '1', 'foo' => 'bar'} }
  let(:cookie)         { {'foo' => 'bar', 'bar' => 'baz'} }
  let(:headers)        { {'X-Foo' => 'bar', 'X-Bar' => 'baz'} }
  let(:form_data)      { {'id' => '1', 'foo' => 'bar'} }

  subject { described_class.new(url) }

  describe "#initialize" do
    it "must set #url" do
      expect(subject.url).to be(url)
    end

    it "must default #request_method to :get" do
      expect(subject.request_method).to be(:get)
    end

    it "must default #user to nil" do
      expect(subject.user).to be(nil)
    end

    it "must default #password to nil" do
      expect(subject.password).to be(nil)
    end

    it "must default #referer to nil" do
      expect(subject.referer).to be(nil)
    end

    it "must default #query_params to nil" do
      expect(subject.query_params).to be(nil)
    end

    it "must default #cookie to nil" do
      expect(subject.cookie).to be(nil)
    end

    it "must default #headers to nil" do
      expect(subject.headers).to be(nil)
    end

    it "must default #form_data to nil" do
      expect(subject.form_data).to be(nil)
    end

    context "when the `request_method:` keyword is given" do
      subject { described_class.new(url, request_method: request_method) }

      it "must set #request_method" do
        expect(subject.request_method).to be(request_method)
      end
    end

    context "when the `user:` keyword is given" do
      subject { described_class.new(url, user: user) }

      it "must set #user" do
        expect(subject.user).to be(user)
      end
    end

    context "when the `password:` keyword is given" do
      subject { described_class.new(url, password: password) }

      it "must set #password" do
        expect(subject.password).to be(password)
      end
    end

    context "when the `referer:` keyword is given" do
      subject { described_class.new(url, referer: referer) }

      it "must set #referer" do
        expect(subject.referer).to be(referer)
      end
    end

    context "when the `query_params:` keyword is given" do
      subject { described_class.new(url, query_params: query_params) }

      it "must set #query_params" do
        expect(subject.query_params).to be(query_params)
      end

      it "must set the #query_params of #url" do
        expect(subject.url.query_params).to eq(query_params)
      end
    end

    context "when the `cookie:` keyword is given" do
      subject { described_class.new(url, cookie: cookie) }

      it "must initialize #cookie to a Ronin::Support::Network::HTTP::Cookie" do
        expect(subject.cookie).to be_kind_of(Ronin::Support::Network::HTTP::Cookie)
      end

      it "must populate #cookie with the cookie values" do
        expect(subject.cookie.params).to eq(cookie)
      end
    end

    context "when the `headers:` keyword is given" do
      subject { described_class.new(url, headers: headers) }

      it "must set #headers" do
        expect(subject.headers).to be(headers)
      end
    end

    context "when the `form_data:` keyword is given" do
      subject { described_class.new(url, form_data: form_data) }

      it "must set #form_data" do
        expect(subject.form_data).to be(form_data)
      end
    end
  end

  describe "#to_curl" do
    it "must return \"curl 'URL'\" in the command" do
      expect(subject.to_curl).to eq("curl '#{url}'")
    end

    context "when #request_method is not :get" do
      subject { described_class.new(url, request_method: :put) }

      it "must include '--request METHOD' in the command" do
        expect(subject.to_curl).to eq("curl --request PUT '#{url}'")
      end
    end

    context "when #user is set" do
      subject { described_class.new(url, user: user) }

      it "must include \"--user 'user:'\" in the command" do
        expect(subject.to_curl).to eq("curl --user '#{user}:' '#{url}'")
      end
    end

    context "when #password is set" do
      subject { described_class.new(url, password: password) }

      it "must include \"--user ':password'\" in the command" do
        expect(subject.to_curl).to eq("curl --user ':#{password}' '#{url}'")
      end
    end

    context "when #user and #password are set" do
      subject { described_class.new(url, user: user, password: password) }

      it "must include \"--user 'user:password'\" in the command" do
        expect(subject.to_curl).to eq("curl --user '#{user}:#{password}' '#{url}'")
      end
    end

    context "when #referer is set" do
      subject { described_class.new(url, referer: referer) }

      it "must include \"--referer '...'\" in the command" do
        expect(subject.to_curl).to eq("curl --referer '#{referer}' '#{url}'")
      end
    end

    context "when initialized with the `query_params:` keyword argument" do
      subject { described_class.new(url, query_params: query_params) }

      let(:merged_url) do
        url.dup.tap do |new_url|
          new_url.query_params = query_params
        end
      end

      it "must merge the query params into in the URL" do
        expect(subject.to_curl).to eq("curl '#{merged_url}'")
      end
    end

    context "when #cookies is not empty" do
      subject { described_class.new(url, cookie: cookie) }

      it "must include \"--cookie '...'\" in the command" do
        expect(subject.to_curl).to eq("curl --cookie '#{subject.cookie}' '#{url}'")
      end
    end

    context "when #headers is not empty" do
      subject { described_class.new(url, headers: headers) }

      it "must include \"--header 'name=value' ...\" in the command" do
        expect(subject.to_curl).to eq("curl --header '#{headers.keys[0]}: #{headers.values[0]}' --header '#{headers.keys[1]}: #{headers.values[1]}' '#{url}'")
      end
    end

    context "when #form_data is not empty" do
      subject { described_class.new(url, form_data: form_data) }

      it "must include \"--form-string '...'\" in the command" do
        encoded_form_data = URI.encode_www_form(form_data)

        expect(subject.to_curl).to eq("curl --form-string '#{encoded_form_data}' '#{url}'")
      end
    end
  end

  describe "#to_http" do
    it "must return \"GET /path?query_params... HTTP/1.1\" in the command" do
      expect(subject.to_http).to eq(
        "GET #{url.request_uri} HTTP/1.1\r\n"
      )
    end

    context "when #request_method is not :get" do
      subject { described_class.new(url, request_method: :put) }

      it "must change the request method" do
        expect(subject.to_http).to eq(
          "PUT #{url.request_uri} HTTP/1.1\r\n"
        )
      end
    end

    context "when #user is set" do
      subject { described_class.new(url, user: user) }

      it "must include the 'Authorization: Basic ...' header" do
        basic_auth = ["#{user}:"].pack('m0')

        expect(subject.to_http).to eq(
          [
            "GET #{url.request_uri} HTTP/1.1",
            "Authorization: Basic #{basic_auth}",
            ''
          ].join("\r\n")
        )
      end
    end

    context "when #password is set" do
      subject { described_class.new(url, password: password) }

      it "must include the 'Authorization: Basic ...' header" do
        basic_auth = [":#{password}"].pack('m0')

        expect(subject.to_http).to eq(
          [
            "GET #{url.request_uri} HTTP/1.1",
            "Authorization: Basic #{basic_auth}",
            ''
          ].join("\r\n")
        )
      end
    end

    context "when #user and #password are set" do
      subject { described_class.new(url, user: user, password: password) }

      it "must include the 'Authorization: Basic ...' header" do
        basic_auth = ["#{user}:#{password}"].pack('m0')

        expect(subject.to_http).to eq(
          [
            "GET #{url.request_uri} HTTP/1.1",
            "Authorization: Basic #{basic_auth}",
            ''
          ].join("\r\n")
        )
      end
    end

    context "when #referer is set" do
      subject { described_class.new(url, referer: referer) }

      it "must include the 'Referer: ...' header" do
        expect(subject.to_http).to eq(
          [
            "GET #{url.request_uri} HTTP/1.1",
            "Referer: #{referer}",
            ''
          ].join("\r\n")
        )
      end
    end

    context "when initialized with the `query_params:` keyword argument" do
      subject { described_class.new(url, query_params: query_params) }

      let(:merged_url) do
        url.dup.tap do |new_url|
          new_url.query_params = query_params
        end
      end

      it "must merge the query params into in the URL" do
        expect(subject.to_http).to eq(
          "GET #{merged_url.request_uri} HTTP/1.1\r\n"
        )
      end
    end

    context "when #cookies is not empty" do
      subject { described_class.new(url, cookie: cookie) }

      it "must include the 'Cookie: ...' header" do
        expect(subject.to_http).to eq(
          [
            "GET #{url.request_uri} HTTP/1.1",
            "Cookie: #{subject.cookie}",
            ''
          ].join("\r\n")
        )
      end
    end

    context "when #headers is not empty" do
      subject { described_class.new(url, headers: headers) }

      it "must include the header names and values" do
        expect(subject.to_http).to eq(
          [
            "GET #{url.request_uri} HTTP/1.1",
            "#{headers.keys[0]}: #{headers.values[0]}",
            "#{headers.keys[1]}: #{headers.values[1]}",
            ''
          ].join("\r\n")
        )
      end
    end

    context "when #form_data is not empty" do
      subject { described_class.new(url, form_data: form_data) }

      it "must include the 'Content-Type: x-www-form-urlencoded' header and form body" do
        encoded_form_data = URI.encode_www_form(form_data)

        expect(subject.to_http).to eq(
          [
            "GET #{url.request_uri} HTTP/1.1",
            'Content-Type: x-www-form-urlencoded',
            '',
            encoded_form_data,
            ''
          ].join("\r\n")
        )
      end
    end
  end
end
