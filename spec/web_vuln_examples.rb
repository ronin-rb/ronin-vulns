require 'rspec'

RSpec.shared_examples_for "Ronin::Vulns::WebVuln#initialize examples" do
  let(:param) { 'vuln' }
  let(:url)   { URI("https://example.com/page.php?q=foo&#{param}=bar") }

  subject { described_class.new(url) }

  it "must set #url" do
    expect(subject.url).to eq(url)
  end

  context "when the given url is a String" do
    let(:url) { "https://example.com/page.php?q=foo&#{param}=bar" }

    it "must automatically parse the given URL" do
      expect(subject.url).to eq(URI.parse(url))
    end
  end

  it "must default #http to Ronin::Support::Network::HTTP for the given URL" do
    expect(subject.http).to be_kind_of(Ronin::Support::Network::HTTP)
    expect(subject.http.host).to eq(url.host)
    expect(subject.http.port).to eq(url.port)
  end

  context "when the query_param: keyword is given" do
    subject { described_class.new(url, query_param: param) }

    it "must set #query_param" do
      expect(subject.query_param).to eq(param)
    end
  end

  context "when the header_name: keyword is given" do
    subject { described_class.new(url, header_name: param) }

    it "must set #header_name" do
      expect(subject.header_name).to eq(param)
    end
  end

  context "when the cookie_param: keyword is given" do
    subject { described_class.new(url, cookie_param: param) }

    it "must set #cookie_param" do
      expect(subject.cookie_param).to eq(param)
    end
  end

  context "when the form_param: keyword is given" do
    subject { described_class.new(url, form_param: param) }

    it "must set #form_param" do
      expect(subject.form_param).to eq(param)
    end
  end

  context "when the http: keyword is given" do
    let(:http) { double('Ronin::Support::Network::HTTP instance') }

    subject { described_class.new(url, http: http) }

    it "must set #http" do
      expect(subject.http).to be(http)
    end
  end

  context "when the request_method: keyword is given" do
    let(:request_method) { :post }

    subject { described_class.new(url, request_method: request_method) }

    it "must set #request_method" do
      expect(subject.request_method).to eq(request_method)
    end
  end

  context "when the user: keyword is given" do
    let(:user) { 'bob' }

    subject { described_class.new(url, user: user) }

    it "must set #user" do
      expect(subject.user).to eq(user)
    end
  end

  context "when the password: keyword is given" do
    let(:password) { 's3cr3t' }

    subject { described_class.new(url, password: password) }

    it "must set #password" do
      expect(subject.password).to eq(password)
    end
  end

  context "when the headers: keyword is given" do
    let(:headers) do
      {'X-Foo' => 'bar' }
    end

    subject { described_class.new(url, headers: headers) }

    it "must set #headers" do
      expect(subject.headers).to be(headers)
    end
  end

  context "when the cookie: keyword is given" do
    let(:cookie) do
      {'foo' => 'bar'}
    end

    subject { described_class.new(url, cookie: cookie) }

    it "must set #cookie" do
      expect(subject.cookie).to be(cookie)
    end
  end

  context "when the form_data: keyword is given" do
    let(:form_data) do
      {'foo' => 'bar'}
    end

    subject { described_class.new(url, form_data: form_data) }

    it "must set #form_data" do
      expect(subject.form_data).to be(form_data)
    end
  end

  context "when the referer: keyword is given" do
    let(:referer) { 'https://example.com/previous/page' }

    subject { described_class.new(url, referer: referer) }

    it "must set #referer" do
      expect(subject.referer).to be(referer)
    end
  end
end

RSpec.shared_examples_for "Ronin::Vulns::WebVuln#exploit examples" do
  context "when #query_param is set" do
    let(:query_param)     { 'id' }
    let(:encoded_payload) { URI::QueryParams.escape(payload) }

    subject { described_class.new(url, query_param: query_param) }

    context "when the URL does not any query params" do
      let(:url) { "https://example.com/page" }

      it "must make a request for the URL with #query_param set to the payload" do
        stub_request(subject.request_method, "#{url}?#{query_param}=#{encoded_payload}")

        subject.exploit(payload)
      end

      context "when #request_method is not :get" do
        let(:request_method) { :post }

        subject do
          described_class.new(url, query_param:    query_param,
                              request_method: request_method)
        end

        it "must send a request with the method of #request_method" do
          stub_request(request_method, "#{url}?#{query_param}=#{encoded_payload}")

          subject.exploit(payload)
        end
      end
    end

    context "when the URL does have additional query params" do
      let(:url) { "https://example.com/page?#{query_param}=1&foo=bar" }

      it "must make a request for the URL with #query_params, but with #query_param overridden to the payload" do
        stub_request(subject.request_method, "https://example.com/page?#{query_param}=#{encoded_payload}&foo=bar")

        subject.exploit(payload)
      end

      context "when #request_method is not :get" do
        let(:request_method) { :post }

        subject do
          described_class.new(url, query_param:    query_param,
                              request_method: request_method)
        end

        it "must send a request with the method of #request_method" do
          stub_request(request_method, "https://example.com/page?#{query_param}=#{encoded_payload}&foo=bar")

          subject.exploit(payload)
        end
      end
    end
  end

  context "when #header_name is set" do
    let(:url)             { "https://example.com/page" }
    let(:header_name)     { 'X-Foo' }
    let(:encoded_payload) { URI.encode_www_form_component(payload) }

    context "when #headers is not set" do
      subject { described_class.new(url, header_name: header_name) }

      it "must make a request for the URL with #header_name set to the payload" do
        stub_request(subject.request_method, url).with(headers: {header_name => payload})

        subject.exploit(payload)
      end

      context "when #request_method is not :get" do
        let(:request_method) { :post }

        subject do
          described_class.new(url, header_name:    header_name,
                              request_method: request_method)
        end

        it "must send a request with the method of #request_method" do
          stub_request(request_method, url).with(headers: {header_name => payload})

          subject.exploit(payload)
        end
      end
    end

    context "when #headers is set" do
      let(:headers) do
        {header_name => 'foo', 'X-Bar' => 'bar'}
      end

      subject do
        described_class.new(url, header_name: header_name, headers: headers)
      end

      it "must make a request for the URL with the #headers, but with #header_name overridden with the payload" do
        stub_request(subject.request_method, url).with(headers: headers.merge(header_name => payload))

        subject.exploit(payload)
      end

      context "when #request_method is not :get" do
        let(:request_method) { :post }

        subject do
          described_class.new(url, header_name:    header_name,
                              request_method: request_method,
                              headers:        headers)
        end

        it "must send a request with the method of #request_method" do
          stub_request(request_method, url).with(headers: headers.merge(header_name => payload))

          subject.exploit(payload)
        end
      end
    end
  end

  context "when #cookie_param is set" do
    let(:url)             { "https://example.com/page" }
    let(:cookie_param)    { 'foo' }
    let(:encoded_payload) { URI.encode_www_form_component(payload) }

    context "when #cookie is not set" do
      subject { described_class.new(url, cookie_param: cookie_param) }

      it "must make a request for the URL with a 'Cookie' header and with #cookie_param set to the payload" do
        stub_request(subject.request_method, url).with(
          headers: {'Cookie' => "#{cookie_param}=#{encoded_payload}"}
        )

        subject.exploit(payload)
      end

      context "when #request_method is not :get" do
        let(:request_method) { :post }

        subject do
          described_class.new(url, cookie_param:   cookie_param,
                                   request_method: request_method)
        end

        it "must send a request with the method of #request_method" do
          stub_request(request_method, url).with(
            headers: {'Cookie' => "#{cookie_param}=#{encoded_payload}"}
          )

          subject.exploit(payload)
        end
      end
    end

    context "when #cookie is set" do
      let(:cookie) do
        {cookie_param => 'foo', 'bar' => 'baz'}
      end

      subject do
        described_class.new(url, cookie_param: cookie_param, cookie: cookie)
      end

      it "must make a request for the URL with the #cookie value, but with #cookie_param overridden with the payload" do
        stub_request(subject.request_method, url).with(
          headers: {'Cookie' => "#{cookie_param}=#{encoded_payload}; bar=baz"}
        )

        subject.exploit(payload)
      end

      context "when #request_method is not :get" do
        let(:request_method) { :post }

        subject do
          described_class.new(url, cookie_param:   cookie_param,
                                   request_method: request_method,
                                   cookie:         cookie)
        end

        it "must send a request with the method of #request_method" do
          stub_request(request_method, url).with(
            headers: {'Cookie' => "#{cookie_param}=#{encoded_payload}; bar=baz"}
          )

          subject.exploit(payload)
        end
      end
    end
  end

  context "when #form_param is set" do
    let(:url)             { "https://example.com/page" }
    let(:form_param)      { 'foo' }
    let(:encoded_payload) { URI.encode_www_form_component(payload) }

    context "when #form_data is not set" do
      subject { described_class.new(url, form_param: form_param) }

      it "must make a request for the URL with a body and with #form_param set to the payload" do
        stub_request(subject.request_method, url).with(body: "#{form_param}=#{encoded_payload}")

        subject.exploit(payload)
      end

      context "when #request_method is not :get" do
        let(:request_method) { :post }

        subject do
          described_class.new(url, form_param:     form_param,
                                   request_method: request_method)
        end

        it "must send a request with the method of #request_method" do
          stub_request(request_method, url).with(body: "#{form_param}=#{encoded_payload}")

          subject.exploit(payload)
        end
      end
    end

    context "when #form_data is set" do
      let(:form_data) do
        {form_param => 'foo', 'bar' => 'baz'}
      end

      subject do
        described_class.new(url, form_param: form_param, form_data: form_data)
      end

      it "must make a request for the URL with a body containing #form_data, but with #form_param overridden with the payload" do
        stub_request(subject.request_method, url).with(body: "#{form_param}=#{encoded_payload}&bar=baz")

        subject.exploit(payload)
      end

      context "when #request_method is not :get" do
        let(:request_method) { :post }

        subject do
          described_class.new(url, form_param:     form_param,
                                   request_method: request_method,
                                   form_data:      form_data)
        end

        it "must send a request with the method of #request_method" do
          stub_request(request_method, url).with(body: "#{form_param}=#{encoded_payload}&bar=baz")

          subject.exploit(payload)
        end
      end
    end
  end
end
