require 'rspec'

RSpec.shared_examples_for "Ronin::Vuln::Web#initialize examples" do
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
