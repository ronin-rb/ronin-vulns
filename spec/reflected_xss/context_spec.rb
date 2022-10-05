require 'spec_helper'
require 'ronin/vulns/reflected_xss/context'

describe Ronin::Vulns::ReflectedXSS::Context do
  describe "#initialize" do
    let(:location) { :double_quoted_attr_value }
    let(:tag)      { 'div'  }
    let(:attr)     { 'attr' }

    subject { described_class.new(location, tag: tag, attr: attr) }

    it "must set #location" do
      expect(subject.location).to eq(location)
    end

    it "must set #tag" do
      expect(subject.tag).to eq(tag)
    end

    it "must set #attr" do
      expect(subject.attr).to eq(attr)
    end

    context "when the attr: keyword is omitted" do
      subject { described_class.new(location, tag: tag) }

      it "must default #attr to nil" do
        expect(subject.attr).to be(nil)
      end
    end
  end

  describe ".identify" do
    let(:index) { body.index('XSS') }

    subject { described_class.identify(body,index) }

    context "when the index is within a tag's body" do
      let(:body) do
        <<~HTML
        <html>
          <body>
            <p>foo bar baz</p>
            <div>foo XSS bar</p>
            <p>foo bar baz</p>
          </body>
        </html>
        HTML
      end

      it "must return a #{described_class}" do
        expect(subject).to be_kind_of(described_class)
      end

      it "must set #location to :tag_body" do
        expect(subject.location).to eq(:tag_body)
      end

      it "must set #tag" do
        expect(subject.tag).to eq('div')
      end
    end

    context "when the index is within a tag's double-quoted attribute value" do
      let(:body) do
        <<~HTML
        <html>
          <body>
            <p>foo bar baz</p>
            <div attr="valueXSS">foo bar baz</p>
            <p>foo bar baz</p>
          </body>
        </html>
        HTML
      end

      it "must return a #{described_class}" do
        expect(subject).to be_kind_of(described_class)
      end

      it "must set #location to :double_quoted_attr_value" do
        expect(subject.location).to eq(:double_quoted_attr_value)
      end

      it "must set #tag" do
        expect(subject.tag).to eq('div')
      end

      it "must set #attr" do
        expect(subject.attr).to eq('attr')
      end
    end

    context "when the index is within a tag's single-quoted attribute value" do
      let(:body) do
        <<~HTML
        <html>
          <body>
            <p>foo bar baz</p>
            <div attr='valueXSS'>foo bar baz</p>
            <p>foo bar baz</p>
          </body>
        </html>
        HTML
      end

      it "must return a #{described_class}" do
        expect(subject).to be_kind_of(described_class)
      end

      it "must set #location to :single_quoted_attr_value" do
        expect(subject.location).to eq(:single_quoted_attr_value)
      end

      it "must set #tag" do
        expect(subject.tag).to eq('div')
      end

      it "must set #attr" do
        expect(subject.attr).to eq('attr')
      end
    end

    context "when the index is within a tag's unquoted attribute value" do
      let(:body) do
        <<~HTML
        <html>
          <body>
            <p>foo bar baz</p>
            <div attr=valueXSS>foo bar baz</p>
            <p>foo bar baz</p>
          </body>
        </html>
        HTML
      end

      it "must return a #{described_class}" do
        expect(subject).to be_kind_of(described_class)
      end

      it "must set #location to :unquoted_attr_value" do
        expect(subject.location).to eq(:unquoted_attr_value)
      end

      it "must set #tag" do
        expect(subject.tag).to eq('div')
      end

      it "must set #attr" do
        expect(subject.attr).to eq('attr')
      end
    end

    context "when the index is within a tag's attribute name" do
      let(:body) do
        <<~HTML
        <html>
          <body>
            <p>foo bar baz</p>
            <div attrXSS>foo bar baz</p>
            <p>foo bar baz</p>
          </body>
        </html>
        HTML
      end

      it "must return a #{described_class}" do
        expect(subject).to be_kind_of(described_class)
      end

      it "must set #location to :attr_name" do
        expect(subject.location).to eq(:attr_name)
      end

      it "must set #tag" do
        expect(subject.tag).to eq('div')
      end

      it "must set #attr" do
        expect(subject.attr).to eq('attr')
      end
    end

    context "when the index is within a tag's attribute list" do
      let(:body) do
        <<~HTML
        <html>
          <body>
            <p>foo bar baz</p>
            <div attr1="1" attr2='2' attr3 XSS>foo bar baz</p>
            <p>foo bar baz</p>
          </body>
        </html>
        HTML
      end

      it "must return a #{described_class}" do
        expect(subject).to be_kind_of(described_class)
      end

      it "must set #location to :attr_list" do
        expect(subject.location).to eq(:attr_list)
      end

      it "must set #tag" do
        expect(subject.tag).to eq('div')
      end
    end

    context "when the index is within a tag's name" do
      let(:body) do
        <<~HTML
        <html>
          <body>
            <p>foo bar baz</p>
            <divXSS attr1="1" attr2='2' attr3>foo bar baz</div>
            <p>foo bar baz</p>
          </body>
        </html>
        HTML
      end

      it "must return a #{described_class}" do
        expect(subject).to be_kind_of(described_class)
      end

      it "must set #location to :tag_name" do
        expect(subject.location).to eq(:tag_name)
      end

      it "must set #tag" do
        expect(subject.tag).to eq('div')
      end
    end
  end

  describe "#viable?" do
    let(:tag)  { 'div'  }
    let(:attr) { 'attr' }

    subject { described_class.new(location, tag: tag, attr: attr) }

    context "when #location is :double_quoted_attr_value" do
      let(:location) { :double_quoted_attr_value }

      context "and allowed characters contains '>', ' ', '/', '<', and '\"'" do
        let(:allowed_chars) { Set['>', ' ', '/', '<', '"'] }

        it "must return true" do
          expect(subject.viable?(allowed_chars)).to be(true)
        end
      end

      context "but allowed characters does not contain '>'" do
        let(:allowed_chars) { Set[' ', '/', '<', '"'] }

        it "must return false" do
          expect(subject.viable?(allowed_chars)).to be(false)
        end
      end

      context "but allowed characters does not contain ' '" do
        let(:allowed_chars) { Set['>', '/', '<', '"'] }

        it "must return false" do
          expect(subject.viable?(allowed_chars)).to be(false)
        end
      end

      context "but allowed characters does not contain '/'" do
        let(:allowed_chars) { Set['>', ' ', '<', '"'] }

        it "must return false" do
          expect(subject.viable?(allowed_chars)).to be(false)
        end
      end

      context "but allowed characters does not contain '<'" do
        let(:allowed_chars) { Set['>', ' ', '/', '"'] }

        it "must return false" do
          expect(subject.viable?(allowed_chars)).to be(false)
        end
      end

      context "but allowed characters does not contain '\"'" do
        let(:allowed_chars) { Set['>', ' ', '/', '<'] }

        it "must return false" do
          expect(subject.viable?(allowed_chars)).to be(false)
        end
      end
    end

    context "when #location is :single_quoted_attr_value" do
      let(:location) { :single_quoted_attr_value }

      context "and allowed characters contains '>', ' ', '/', '<', and '\\''" do
        let(:allowed_chars) { Set['>', ' ', '/', '<', "'"] }

        it "must return true" do
          expect(subject.viable?(allowed_chars)).to be(true)
        end
      end

      context "but allowed characters does not contain '>'" do
        let(:allowed_chars) { Set[' ', '/', '<', "'"] }

        it "must return false" do
          expect(subject.viable?(allowed_chars)).to be(false)
        end
      end

      context "but allowed characters does not contain ' '" do
        let(:allowed_chars) { Set['>', '/', '<', "'"] }

        it "must return false" do
          expect(subject.viable?(allowed_chars)).to be(false)
        end
      end

      context "but allowed characters does not contain '/'" do
        let(:allowed_chars) { Set['>', ' ', '<', "'"] }

        it "must return false" do
          expect(subject.viable?(allowed_chars)).to be(false)
        end
      end

      context "but allowed characters does not contain '<'" do
        let(:allowed_chars) { Set['>', ' ', '/', "'"] }

        it "must return false" do
          expect(subject.viable?(allowed_chars)).to be(false)
        end
      end

      context "but allowed characters does not contain '\\''" do
        let(:allowed_chars) { Set['>', ' ', '/', '<'] }

        it "must return false" do
          expect(subject.viable?(allowed_chars)).to be(false)
        end
      end
    end

    context "when #location is :unquoted_attr_value" do
      let(:location) { :unquoted_attr_value }

      context "and allowed characters contains '>', ' ', '/', and '<''" do
        let(:allowed_chars) { Set['>', ' ', '/', '<'] }

        it "must return true" do
          expect(subject.viable?(allowed_chars)).to be(true)
        end
      end

      context "but allowed characters does not contain '>'" do
        let(:allowed_chars) { Set[' ', '/', '<'] }

        it "must return false" do
          expect(subject.viable?(allowed_chars)).to be(false)
        end
      end

      context "but allowed characters does not contain ' '" do
        let(:allowed_chars) { Set['>', '/', '<'] }

        it "must return false" do
          expect(subject.viable?(allowed_chars)).to be(false)
        end
      end

      context "but allowed characters does not contain '/'" do
        let(:allowed_chars) { Set['>', ' ', '<'] }

        it "must return false" do
          expect(subject.viable?(allowed_chars)).to be(false)
        end
      end

      context "but allowed characters does not contain '<'" do
        let(:allowed_chars) { Set['>', ' ', '/'] }

        it "must return false" do
          expect(subject.viable?(allowed_chars)).to be(false)
        end
      end
    end

    context "when #location is :attr_name" do
      let(:location) { :attr_name }

      context "and allowed characters contains '>', ' ', '/', and '<''" do
        let(:allowed_chars) { Set['>', ' ', '/', '<'] }

        it "must return true" do
          expect(subject.viable?(allowed_chars)).to be(true)
        end
      end
    end

    context "when #location is :attr_list" do
      let(:location) { :attr_list }

      context "and allowed characters contains '>', ' ', '/', and '<''" do
        let(:allowed_chars) { Set['>', ' ', '/', '<'] }

        it "must return true" do
          expect(subject.viable?(allowed_chars)).to be(true)
        end
      end
    end

    context "when #location is :tag_name" do
      let(:location) { :tag_name }

      context "and allowed characters contains '>', ' ', '/', and '<''" do
        let(:allowed_chars) { Set['>', ' ', '/', '<'] }

        it "must return true" do
          expect(subject.viable?(allowed_chars)).to be(true)
        end
      end
    end

    context "when #location is :tag_body" do
      let(:location) { :tag_body }

      context "and allowed characters contains '>', ' ', '/', and '<''" do
        let(:allowed_chars) { Set['>', ' ', '/', '<'] }

        it "must return true" do
          expect(subject.viable?(allowed_chars)).to be(true)
        end
      end
    end

    context "when #location is an unknown type" do
      let(:location)      { :foo }
      let(:allowed_chars) { Set['>', ' ', '/', '<', '"'] }

      it do
        expect {
          subject.viable?(allowed_chars)
        }.to raise_error(NotImplementedError,"cannot determine viability for unknown XSS location type: #{location.inspect}")
      end
    end
  end
end
