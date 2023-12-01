require 'spec_helper'
require 'ronin/vulns/cli/importable'

require 'ronin/vulns/cli/command'
require 'ronin/vulns/lfi'
require 'ronin/vulns/rfi'
require 'ronin/vulns/sqli'
require 'ronin/vulns/ssti'
require 'ronin/vulns/reflected_xss'
require 'ronin/vulns/open_redirect'
require 'ronin/db'

describe Ronin::Vulns::CLI::Importable do
  module TestCLIImportable
    class TestCommand < Ronin::Vulns::CLI::Command
      include Ronin::Vulns::CLI::Importable
    end
  end

  let(:command_class) { TestCLIImportable::TestCommand }
  subject { command_class.new }

  describe ".included" do
    subject { command_class }

    it "must include Ronin::DB::CLI::DatabaseOptions" do
      expect(subject).to include(Ronin::DB::CLI::DatabaseOptions)
    end
  end

  describe "#import_vuln" do
    let(:url) { 'https://example.com/page.php?id=1' }

    let(:query_param) { 'id' }
    let(:vuln) { Ronin::Vulns::LFI.new(url, query_param: query_param) }

    it "must call Importer.import with the vuln object and call #log_info" do
      expect(Ronin::Vulns::Importer).to receive(:import).with(vuln)
      allow(subject).to receive(:log_info)

      subject.import_vuln(vuln)
    end

    context "when given a Ronin::Vulns::LFI object" do
      before { allow(Ronin::Vulns::Importer).to receive(:import).with(vuln) }

      context "and the #query_param attribute is set" do
        let(:query_param) { 'id' }
        let(:vuln) { Ronin::Vulns::LFI.new(url, query_param: query_param) }

        it "must log 'Imported LFI vulnerability on URL <url> and query param <query_param>'" do
          expect(subject).to receive(:log_info).with(
            "Imported LFI vulnerability on URL #{url} and query param '#{query_param}'"
          )

          subject.import_vuln(vuln)
        end
      end

      context "and the #header_name attribute is set" do
        let(:header_name) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::LFI.new(url, header_name: header_name) }

        it "must log 'Imported LFI vulnerability on URL <url> and Header <header_name>'" do
          expect(subject).to receive(:log_info).with(
            "Imported LFI vulnerability on URL #{url} and Header '#{header_name}'"
          )

          subject.import_vuln(vuln)
        end
      end

      context "and the #cookie_param attribute is set" do
        let(:cookie_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::LFI.new(url, cookie_param: cookie_param) }

        it "must log 'Imported LFI vulnerability on URL <url> and Cookie param <cookie_param>'" do
          expect(subject).to receive(:log_info).with(
            "Imported LFI vulnerability on URL #{url} and Cookie param '#{cookie_param}'"
          )

          subject.import_vuln(vuln)
        end
      end

      context "and the #form_param attribute is set" do
        let(:form_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::LFI.new(url, form_param: form_param) }

        it "must log 'Imported LFI vulnerability on URL <url> and form param <form_param>'" do
          expect(subject).to receive(:log_info).with(
            "Imported LFI vulnerability on URL #{url} and form param '#{form_param}'"
          )

          subject.import_vuln(vuln)
        end
      end
    end

    context "when given a Ronin::Vulns::RFI object" do
      before { allow(Ronin::Vulns::Importer).to receive(:import).with(vuln) }

      context "and the #query_param attribute is set" do
        let(:query_param) { 'id' }
        let(:vuln) { Ronin::Vulns::RFI.new(url, query_param: query_param) }

        it "must log 'Imported RFI vulnerability on URL <url> and query param <query_param>'" do
          expect(subject).to receive(:log_info).with(
            "Imported RFI vulnerability on URL #{url} and query param '#{query_param}'"
          )

          subject.import_vuln(vuln)
        end
      end

      context "and the #header_name attribute is set" do
        let(:header_name) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::RFI.new(url, header_name: header_name) }

        it "must log 'Imported RFI vulnerability on URL <url> and Header <header_name>'" do
          expect(subject).to receive(:log_info).with(
            "Imported RFI vulnerability on URL #{url} and Header '#{header_name}'"
          )

          subject.import_vuln(vuln)
        end
      end

      context "and the #cookie_param attribute is set" do
        let(:cookie_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::RFI.new(url, cookie_param: cookie_param) }

        it "must log 'Imported RFI vulnerability on URL <url> and Cookie param <cookie_param>'" do
          expect(subject).to receive(:log_info).with(
            "Imported RFI vulnerability on URL #{url} and Cookie param '#{cookie_param}'"
          )

          subject.import_vuln(vuln)
        end
      end

      context "and the #form_param attribute is set" do
        let(:form_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::RFI.new(url, form_param: form_param) }

        it "must log 'Imported RFI vulnerability on URL <url> and form param <form_param>'" do
          expect(subject).to receive(:log_info).with(
            "Imported RFI vulnerability on URL #{url} and form param '#{form_param}'"
          )

          subject.import_vuln(vuln)
        end
      end
    end

    context "when given a Ronin::Vulns::SQLI object" do
      before { allow(Ronin::Vulns::Importer).to receive(:import).with(vuln) }

      context "and the #query_param attribute is set" do
        let(:query_param) { 'id' }
        let(:vuln) { Ronin::Vulns::SQLI.new(url, query_param: query_param) }

        it "must log 'Imported SQLI vulnerability on URL <url> and query param <query_param>'" do
          expect(subject).to receive(:log_info).with(
            "Imported SQLi vulnerability on URL #{url} and query param '#{query_param}'"
          )

          subject.import_vuln(vuln)
        end
      end

      context "and the #header_name attribute is set" do
        let(:header_name) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::SQLI.new(url, header_name: header_name) }

        it "must log 'Imported SQLI vulnerability on URL <url> and Header <header_name>'" do
          expect(subject).to receive(:log_info).with(
            "Imported SQLi vulnerability on URL #{url} and Header '#{header_name}'"
          )

          subject.import_vuln(vuln)
        end
      end

      context "and the #cookie_param attribute is set" do
        let(:cookie_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::SQLI.new(url, cookie_param: cookie_param) }

        it "must log 'Imported SQLI vulnerability on URL <url> and Cookie param <cookie_param>'" do
          expect(subject).to receive(:log_info).with(
            "Imported SQLi vulnerability on URL #{url} and Cookie param '#{cookie_param}'"
          )

          subject.import_vuln(vuln)
        end
      end

      context "and the #form_param attribute is set" do
        let(:form_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::SQLI.new(url, form_param: form_param) }

        it "must log 'Imported SQLI vulnerability on URL <url> and form param <form_param>'" do
          expect(subject).to receive(:log_info).with(
            "Imported SQLi vulnerability on URL #{url} and form param '#{form_param}'"
          )

          subject.import_vuln(vuln)
        end
      end
    end

    context "when given a Ronin::Vulns::SSTI object" do
      before { allow(Ronin::Vulns::Importer).to receive(:import).with(vuln) }

      context "and the #query_param attribute is set" do
        let(:query_param) { 'id' }
        let(:vuln) { Ronin::Vulns::SSTI.new(url, query_param: query_param) }

        it "must log 'Imported SSTI vulnerability on URL <url> and query param <query_param>'" do
          expect(subject).to receive(:log_info).with(
            "Imported SSTI vulnerability on URL #{url} and query param '#{query_param}'"
          )

          subject.import_vuln(vuln)
        end
      end

      context "and the #header_name attribute is set" do
        let(:header_name) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::SSTI.new(url, header_name: header_name) }

        it "must log 'Imported SSTI vulnerability on URL <url> and Header <header_name>'" do
          expect(subject).to receive(:log_info).with(
            "Imported SSTI vulnerability on URL #{url} and Header '#{header_name}'"
          )

          subject.import_vuln(vuln)
        end
      end

      context "and the #cookie_param attribute is set" do
        let(:cookie_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::SSTI.new(url, cookie_param: cookie_param) }

        it "must log 'Imported SSTI vulnerability on URL <url> and Cookie param <cookie_param>'" do
          expect(subject).to receive(:log_info).with(
            "Imported SSTI vulnerability on URL #{url} and Cookie param '#{cookie_param}'"
          )

          subject.import_vuln(vuln)
        end
      end

      context "and the #form_param attribute is set" do
        let(:form_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::SSTI.new(url, form_param: form_param) }

        it "must log 'Imported SSTI vulnerability on URL <url> and form param <form_param>'" do
          expect(subject).to receive(:log_info).with(
            "Imported SSTI vulnerability on URL #{url} and form param '#{form_param}'"
          )

          subject.import_vuln(vuln)
        end
      end
    end

    context "when given a Ronin::Vulns::OpenRedirect object" do
      before { allow(Ronin::Vulns::Importer).to receive(:import).with(vuln) }

      context "and the #query_param attribute is set" do
        let(:query_param) { 'id' }
        let(:vuln) { Ronin::Vulns::OpenRedirect.new(url, query_param: query_param) }

        it "must log 'Imported Open Redirect vulnerability on URL <url> and query param <query_param>'" do
          expect(subject).to receive(:log_info).with(
            "Imported Open Redirect vulnerability on URL #{url} and query param '#{query_param}'"
          )

          subject.import_vuln(vuln)
        end
      end

      context "and the #header_name attribute is set" do
        let(:header_name) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::OpenRedirect.new(url, header_name: header_name) }

        it "must log 'Imported Open Redirect vulnerability on URL <url> and Header <header_name>'" do
          expect(subject).to receive(:log_info).with(
            "Imported Open Redirect vulnerability on URL #{url} and Header '#{header_name}'"
          )

          subject.import_vuln(vuln)
        end
      end

      context "and the #cookie_param attribute is set" do
        let(:cookie_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::OpenRedirect.new(url, cookie_param: cookie_param) }

        it "must log 'Imported Open Redirect vulnerability on URL <url> and Cookie param <cookie_param>'" do
          expect(subject).to receive(:log_info).with(
            "Imported Open Redirect vulnerability on URL #{url} and Cookie param '#{cookie_param}'"
          )

          subject.import_vuln(vuln)
        end
      end

      context "and the #form_param attribute is set" do
        let(:form_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::OpenRedirect.new(url, form_param: form_param) }

        it "must log 'Imported Open Redirect vulnerability on URL <url> and form param <form_param>'" do
          expect(subject).to receive(:log_info).with(
            "Imported Open Redirect vulnerability on URL #{url} and form param '#{form_param}'"
          )

          subject.import_vuln(vuln)
        end
      end
    end

    context "when given a Ronin::Vulns::ReflectedXSS object" do
      before { allow(Ronin::Vulns::Importer).to receive(:import).with(vuln) }

      context "and the #query_param attribute is set" do
        let(:query_param) { 'id' }
        let(:vuln) { Ronin::Vulns::ReflectedXSS.new(url, query_param: query_param) }

        it "must log 'Imported reflected XSS vulnerability on URL <url> and query param <query_param>'" do
          expect(subject).to receive(:log_info).with(
            "Imported reflected XSS vulnerability on URL #{url} and query param '#{query_param}'"
          )

          subject.import_vuln(vuln)
        end
      end

      context "and the #header_name attribute is set" do
        let(:header_name) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::ReflectedXSS.new(url, header_name: header_name) }

        it "must log 'Imported reflected XSS vulnerability on URL <url> and Header <header_name>'" do
          expect(subject).to receive(:log_info).with(
            "Imported reflected XSS vulnerability on URL #{url} and Header '#{header_name}'"
          )

          subject.import_vuln(vuln)
        end
      end

      context "and the #cookie_param attribute is set" do
        let(:cookie_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::ReflectedXSS.new(url, cookie_param: cookie_param) }

        it "must log 'Imported reflected XSS vulnerability on URL <url> and Cookie param <cookie_param>'" do
          expect(subject).to receive(:log_info).with(
            "Imported reflected XSS vulnerability on URL #{url} and Cookie param '#{cookie_param}'"
          )

          subject.import_vuln(vuln)
        end
      end

      context "and the #form_param attribute is set" do
        let(:form_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::ReflectedXSS.new(url, form_param: form_param) }

        it "must log 'Imported reflected XSS vulnerability on URL <url> and form param <form_param>'" do
          expect(subject).to receive(:log_info).with(
            "Imported reflected XSS vulnerability on URL #{url} and form param '#{form_param}'"
          )

          subject.import_vuln(vuln)
        end
      end
    end
  end
end
