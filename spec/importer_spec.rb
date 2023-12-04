require 'spec_helper'
require 'ronin/vulns/importer'
require 'ronin/vulns/lfi'
require 'ronin/vulns/rfi'
require 'ronin/vulns/sqli'
require 'ronin/vulns/ssti'
require 'ronin/vulns/command_injection'
require 'ronin/vulns/open_redirect'
require 'ronin/vulns/reflected_xss'
require 'ronin/db'

describe Ronin::Vulns::Importer do
  describe ".importer" do
    before(:all) do
      Ronin::DB.connect({adapter: :sqlite3, database: ':memory:'})
    end

    after(:all) { Ronin::DB::WebVuln.destroy_all }

    let(:query_param)  { 'q' }
    let(:header_name)  { 'X-Header-Name' }
    let(:cookie_param) { 'cookie-param' }
    let(:form_param)   { 'form-param' }
    let(:vuln_kwargs) do
      {query_param: query_param}
    end

    let(:url)  { URI("https://example.com/page.php?#{query_param}=1") }
    let(:vuln) { vuln_class.new(url,**vuln_kwargs) }

    shared_examples_for "importing common attributes" do
      it "must return a saved Ronin::DB::WebVuln record" do
        imported_vuln = subject.import(vuln)

        expect(imported_vuln).to be_kind_of(Ronin::DB::WebVuln)
        expect(imported_vuln).to be_persisted
      end

      it "must set the #url field in the Ronin::DB::WebVuln record" do
        imported_vuln = subject.import(vuln)

        expect(imported_vuln.url).to be_kind_of(Ronin::DB::URL)
        expect(imported_vuln.url).to be_persisted
      end

      context "when #query_param is set on the vuln object" do
        let(:vuln) do
          vuln_class.new(url, query_param: query_param)
        end

        it "must set the #query_param field to the vuln object's #query_param value" do
          imported_vuln = subject.import(vuln)

          expect(imported_vuln.query_param).to eq(query_param)
        end
      end

      context "when #header_name is set on the vuln object" do
        let(:vuln) do
          vuln_class.new(url, header_name: header_name)
        end

        it "must set the #header_name field to the vuln object's #header_name value" do
          imported_vuln = subject.import(vuln)

          expect(imported_vuln.header_name).to eq(header_name)
        end
      end

      context "when #cookie_param is set on the vuln object" do
        let(:vuln) do
          vuln_class.new(url, cookie_param: cookie_param)
        end

        it "must set the #cookie_param field to the vuln object's #cookie_param value" do
          imported_vuln = subject.import(vuln)

          expect(imported_vuln.cookie_param).to eq(cookie_param)
        end
      end

      context "when #form_param is set on the vuln object" do
        let(:vuln) do
          vuln_class.new(url, form_param: form_param)
        end

        it "must set the #form_param field to the vuln object's #form_param value" do
          imported_vuln = subject.import(vuln)

          expect(imported_vuln.form_param).to eq(form_param)
        end
      end
    end

    context "when given an Ronin::Vulns::LFI object" do
      let(:vuln_class) { Ronin::Vulns::LFI }

      include_context "importing common attributes"

      context "when #os is set on the LFI object" do
        let(:os) { :windows }
        let(:vuln) do
          vuln_class.new(url, query_param: query_param, os: os)
        end

        it "must set the #lfi_os field" do
          imported_vuln = subject.import(vuln)

          expect(imported_vuln.lfi_os).to eq(os.to_s)
        end
      end

      context "when #depth is set on the LFI object" do
        let(:depth) { 9 }
        let(:vuln) do
          vuln_class.new(url, query_param: query_param, depth: depth)
        end

        it "must set the #lfi_depth field" do
          imported_vuln = subject.import(vuln)

          expect(imported_vuln.lfi_depth).to eq(depth)
        end
      end

      context "when #filter_bypass is set on the LFI vuln object" do
        let(:filter_bypass) { :null_byte }
        let(:vuln) do
          vuln_class.new(url, query_param:   query_param,
                              filter_bypass: filter_bypass)
        end

        it "must set the #lfi_filter_bypass field" do
          imported_vuln = subject.import(vuln)

          expect(imported_vuln.lfi_filter_bypass).to eq(filter_bypass.to_s)
        end
      end
    end

    context "when given an Ronin::Vulns::RFI object" do
      let(:vuln_class) { Ronin::Vulns::RFI }

      include_context "importing common attributes"

      it "must set #rfi_script_lang to that of the RFI vuln object's #script_lang" do
        imported_vuln = subject.import(vuln)

        expect(imported_vuln.rfi_script_lang).to eq(vuln.script_lang.to_s)
      end

      it "must set #rfi_test_script_url to that of the RFI vuln object's #script_lang" do
        imported_vuln = subject.import(vuln)

        expect(imported_vuln.rfi_script_lang).to eq(vuln.script_lang.to_s)
      end

      context "when #filter_bypass is set on the RFI vuln object" do
        let(:filter_bypass) { :null_byte }
        let(:vuln) do
          vuln_class.new(url, query_param:   query_param,
                              filter_bypass: filter_bypass)
        end

        it "must set the #rfi_filter_bypass field" do
          imported_vuln = subject.import(vuln)

          expect(imported_vuln.rfi_filter_bypass).to eq(filter_bypass.to_s)
        end
      end
    end

    context "when given an Ronin::Vulns::SQLI object" do
      let(:vuln_class) { Ronin::Vulns::SQLI }

      include_context "importing common attributes"

      context "when #escape_quote is set on the SQLI vuln object" do
        let(:vuln) do
          vuln_class.new(url, query_param:  query_param,
                              escape_quote: true)
        end

        it "must set the #sqli_escape_quote field to true" do
          imported_vuln = subject.import(vuln)

          expect(imported_vuln.sqli_escape_quote).to be(true)
        end
      end

      context "when #escape_parens is set on the SQLI vuln object" do
        let(:vuln) do
          vuln_class.new(url, query_param:   query_param,
                              escape_parens: true)
        end

        it "must set the #sqli_escape_parens field to true" do
          imported_vuln = subject.import(vuln)

          expect(imported_vuln.sqli_escape_parens).to be(true)
        end
      end

      context "when #terminate is set on the SQLI vuln object" do
        let(:vuln) do
          vuln_class.new(url, query_param:  query_param,
                              terminate:    true)
        end

        it "must set the #sqli_terminate field to true" do
          imported_vuln = subject.import(vuln)

          expect(imported_vuln.sqli_terminate).to be(true)
        end
      end
    end

    context "when given an Ronin::Vulns::SSTI object" do
      let(:vuln_class) { Ronin::Vulns::SSTI }

      include_context "importing common attributes"

      context "when #escape_type is set on the SSTI vuln object" do
        let(:vuln) do
          vuln_class.new(url, query_param:  query_param,
                              escape:       :double_curly_braces)
        end

        it "must set the #ssti_escape_type field to the SSTI vuln object's #escape_type" do
          imported_vuln = subject.import(vuln)

          expect(imported_vuln.ssti_escape_type).to eq(vuln.escape_type.to_s)
        end
      end
    end

    context "when given an Ronin::Vulns::CommandInjection object" do
      let(:vuln_class) { Ronin::Vulns::CommandInjection }

      include_context "importing common attributes"

      context "when #escape_quote is set on the CommandInjection vuln object" do
        let(:vuln) do
          vuln_class.new(url, query_param:  query_param,
                              escape_quote: "'")
        end

        it "must set the #command_injection_escape_quote field to the CommandInjection vuln object's #escape_type" do
          imported_vuln = subject.import(vuln)

          expect(imported_vuln.command_injection_escape_quote).to eq(vuln.escape_quote)
        end
      end

      context "when #escape_operator is set on the CommandInjection vuln object" do
        let(:vuln) do
          vuln_class.new(url, query_param:     query_param,
                              escape_operator: ";")
        end

        it "must set the #command_injection_escape_operator field to the CommandInjection vuln object's #escape_type" do
          imported_vuln = subject.import(vuln)

          expect(imported_vuln.command_injection_escape_operator).to eq(vuln.escape_operator)
        end
      end

      context "when #terminator is set on the CommandInjection vuln object" do
        let(:vuln) do
          vuln_class.new(url, query_param: query_param,
                              terminator:  "#")
        end

        it "must set the #command_injection_terminator field to the CommandInjection vuln object's #escape_type" do
          imported_vuln = subject.import(vuln)

          expect(imported_vuln.command_injection_terminator).to eq(vuln.terminator)
        end
      end
    end

    context "when given an Ronin::Vulns::OpenRedirect object" do
      let(:vuln_class) { Ronin::Vulns::OpenRedirect }

      include_context "importing common attributes"
    end

    context "when given an Ronin::Vulns::ReflectedXSS object" do
      let(:vuln_class) { Ronin::Vulns::ReflectedXSS }

      include_context "importing common attributes"
    end
  end
end
