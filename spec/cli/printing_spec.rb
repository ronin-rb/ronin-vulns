require 'spec_helper'
require 'ronin/vulns/cli/printing'

require 'ronin/vulns/cli/command'
require 'ronin/vulns/lfi'
require 'ronin/vulns/rfi'
require 'ronin/vulns/sqli'
require 'ronin/vulns/ssti'
require 'ronin/vulns/reflected_xss'
require 'ronin/vulns/open_redirect'

require 'stringio'

describe Ronin::Vulns::CLI::Printing do
  let(:url) { 'https://example.com/page.php?id=1' }

  module TestCLIPrinting
    class TestCommand < Ronin::Vulns::CLI::Command
      include Ronin::Vulns::CLI::Printing
    end
  end

  let(:command_class) { TestCLIPrinting::TestCommand }
  subject { command_class.new }

  describe "#log_vuln" do
    context "when given a Ronin::Vulns::LFI object" do
      context "and the #query_param attribute is set" do
        let(:query_param) { 'id' }
        let(:vuln) { Ronin::Vulns::LFI.new(url, query_param: query_param) }

        it "must log 'Found LFI on <url> via query param <query_param>!'" do
          expect(subject).to receive(:log_warn).with(
            "Found LFI on #{url} via query param '#{query_param}'!"
          )

          subject.log_vuln(vuln)
        end
      end

      context "and the #header_name attribute is set" do
        let(:header_name) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::LFI.new(url, header_name: header_name) }

        it "must log 'Found LFI on <url> via Header <header_name>!'" do
          expect(subject).to receive(:log_warn).with(
            "Found LFI on #{url} via Header '#{header_name}'!"
          )

          subject.log_vuln(vuln)
        end
      end

      context "and the #cookie_param attribute is set" do
        let(:cookie_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::LFI.new(url, cookie_param: cookie_param) }

        it "must log 'Found LFI on <url> via Cookie param <cookie_param>!'" do
          expect(subject).to receive(:log_warn).with(
            "Found LFI on #{url} via Cookie param '#{cookie_param}'!"
          )

          subject.log_vuln(vuln)
        end
      end

      context "and the #form_param attribute is set" do
        let(:form_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::LFI.new(url, form_param: form_param) }

        it "must log 'Found LFI on <url> via form param <form_param>!'" do
          expect(subject).to receive(:log_warn).with(
            "Found LFI on #{url} via form param '#{form_param}'!"
          )

          subject.log_vuln(vuln)
        end
      end
    end

    context "when given a Ronin::Vulns::RFI object" do
      context "and the #query_param attribute is set" do
        let(:query_param) { 'id' }
        let(:vuln) { Ronin::Vulns::RFI.new(url, query_param: query_param) }

        it "must log 'Found RFI on <url> via query param <query_param>!'" do
          expect(subject).to receive(:log_warn).with(
            "Found RFI on #{url} via query param '#{query_param}'!"
          )

          subject.log_vuln(vuln)
        end
      end

      context "and the #header_name attribute is set" do
        let(:header_name) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::RFI.new(url, header_name: header_name) }

        it "must log 'Found RFI on <url> via Header <header_name>!'" do
          expect(subject).to receive(:log_warn).with(
            "Found RFI on #{url} via Header '#{header_name}'!"
          )

          subject.log_vuln(vuln)
        end
      end

      context "and the #cookie_param attribute is set" do
        let(:cookie_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::RFI.new(url, cookie_param: cookie_param) }

        it "must log 'Found RFI on <url> via Cookie param <cookie_param>!'" do
          expect(subject).to receive(:log_warn).with(
            "Found RFI on #{url} via Cookie param '#{cookie_param}'!"
          )

          subject.log_vuln(vuln)
        end
      end

      context "and the #form_param attribute is set" do
        let(:form_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::RFI.new(url, form_param: form_param) }

        it "must log 'Found RFI on <url> via form param <form_param>!'" do
          expect(subject).to receive(:log_warn).with(
            "Found RFI on #{url} via form param '#{form_param}'!"
          )

          subject.log_vuln(vuln)
        end
      end
    end

    context "when given a Ronin::Vulns::SQLI object" do
      context "and the #query_param attribute is set" do
        let(:query_param) { 'id' }
        let(:vuln) { Ronin::Vulns::SQLI.new(url, query_param: query_param) }

        it "must log 'Found SQLI on <url> via query param <query_param>!'" do
          expect(subject).to receive(:log_warn).with(
            "Found SQLi on #{url} via query param '#{query_param}'!"
          )

          subject.log_vuln(vuln)
        end
      end

      context "and the #header_name attribute is set" do
        let(:header_name) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::SQLI.new(url, header_name: header_name) }

        it "must log 'Found SQLI on <url> via Header <header_name>!'" do
          expect(subject).to receive(:log_warn).with(
            "Found SQLi on #{url} via Header '#{header_name}'!"
          )

          subject.log_vuln(vuln)
        end
      end

      context "and the #cookie_param attribute is set" do
        let(:cookie_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::SQLI.new(url, cookie_param: cookie_param) }

        it "must log 'Found SQLI on <url> via Cookie param <cookie_param>!'" do
          expect(subject).to receive(:log_warn).with(
            "Found SQLi on #{url} via Cookie param '#{cookie_param}'!"
          )

          subject.log_vuln(vuln)
        end
      end

      context "and the #form_param attribute is set" do
        let(:form_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::SQLI.new(url, form_param: form_param) }

        it "must log 'Found SQLI on <url> via form param <form_param>!'" do
          expect(subject).to receive(:log_warn).with(
            "Found SQLi on #{url} via form param '#{form_param}'!"
          )

          subject.log_vuln(vuln)
        end
      end
    end

    context "when given a Ronin::Vulns::SSTI object" do
      context "and the #query_param attribute is set" do
        let(:query_param) { 'id' }
        let(:vuln) { Ronin::Vulns::SSTI.new(url, query_param: query_param) }

        it "must log 'Found SSTI on <url> via query param <query_param>!'" do
          expect(subject).to receive(:log_warn).with(
            "Found SSTI on #{url} via query param '#{query_param}'!"
          )

          subject.log_vuln(vuln)
        end
      end

      context "and the #header_name attribute is set" do
        let(:header_name) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::SSTI.new(url, header_name: header_name) }

        it "must log 'Found SSTI on <url> via Header <header_name>!'" do
          expect(subject).to receive(:log_warn).with(
            "Found SSTI on #{url} via Header '#{header_name}'!"
          )

          subject.log_vuln(vuln)
        end
      end

      context "and the #cookie_param attribute is set" do
        let(:cookie_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::SSTI.new(url, cookie_param: cookie_param) }

        it "must log 'Found SSTI on <url> via Cookie param <cookie_param>!'" do
          expect(subject).to receive(:log_warn).with(
            "Found SSTI on #{url} via Cookie param '#{cookie_param}'!"
          )

          subject.log_vuln(vuln)
        end
      end

      context "and the #form_param attribute is set" do
        let(:form_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::SSTI.new(url, form_param: form_param) }

        it "must log 'Found SSTI on <url> via form param <form_param>!'" do
          expect(subject).to receive(:log_warn).with(
            "Found SSTI on #{url} via form param '#{form_param}'!"
          )

          subject.log_vuln(vuln)
        end
      end
    end

    context "when given a Ronin::Vulns::OpenRedirect object" do
      context "and the #query_param attribute is set" do
        let(:query_param) { 'id' }
        let(:vuln) { Ronin::Vulns::OpenRedirect.new(url, query_param: query_param) }

        it "must log 'Found Open Redirect on <url> via query param <query_param>!'" do
          expect(subject).to receive(:log_warn).with(
            "Found Open Redirect on #{url} via query param '#{query_param}'!"
          )

          subject.log_vuln(vuln)
        end
      end

      context "and the #header_name attribute is set" do
        let(:header_name) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::OpenRedirect.new(url, header_name: header_name) }

        it "must log 'Found Open Redirect on <url> via Header <header_name>!'" do
          expect(subject).to receive(:log_warn).with(
            "Found Open Redirect on #{url} via Header '#{header_name}'!"
          )

          subject.log_vuln(vuln)
        end
      end

      context "and the #cookie_param attribute is set" do
        let(:cookie_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::OpenRedirect.new(url, cookie_param: cookie_param) }

        it "must log 'Found Open Redirect on <url> via Cookie param <cookie_param>!'" do
          expect(subject).to receive(:log_warn).with(
            "Found Open Redirect on #{url} via Cookie param '#{cookie_param}'!"
          )

          subject.log_vuln(vuln)
        end
      end

      context "and the #form_param attribute is set" do
        let(:form_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::OpenRedirect.new(url, form_param: form_param) }

        it "must log 'Found Open Redirect on <url> via form param <form_param>!'" do
          expect(subject).to receive(:log_warn).with(
            "Found Open Redirect on #{url} via form param '#{form_param}'!"
          )

          subject.log_vuln(vuln)
        end
      end
    end

    context "when given a Ronin::Vulns::ReflectedXSS object" do
      context "and the #query_param attribute is set" do
        let(:query_param) { 'id' }
        let(:vuln) { Ronin::Vulns::ReflectedXSS.new(url, query_param: query_param) }

        it "must log 'Found reflected XSS on <url> via query param <query_param>!'" do
          expect(subject).to receive(:log_warn).with(
            "Found reflected XSS on #{url} via query param '#{query_param}'!"
          )

          subject.log_vuln(vuln)
        end
      end

      context "and the #header_name attribute is set" do
        let(:header_name) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::ReflectedXSS.new(url, header_name: header_name) }

        it "must log 'Found reflected XSS on <url> via Header <header_name>!'" do
          expect(subject).to receive(:log_warn).with(
            "Found reflected XSS on #{url} via Header '#{header_name}'!"
          )

          subject.log_vuln(vuln)
        end
      end

      context "and the #cookie_param attribute is set" do
        let(:cookie_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::ReflectedXSS.new(url, cookie_param: cookie_param) }

        it "must log 'Found reflected XSS on <url> via Cookie param <cookie_param>!'" do
          expect(subject).to receive(:log_warn).with(
            "Found reflected XSS on #{url} via Cookie param '#{cookie_param}'!"
          )

          subject.log_vuln(vuln)
        end
      end

      context "and the #form_param attribute is set" do
        let(:form_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::ReflectedXSS.new(url, form_param: form_param) }

        it "must log 'Found reflected XSS on <url> via form param <form_param>!'" do
          expect(subject).to receive(:log_warn).with(
            "Found reflected XSS on #{url} via form param '#{form_param}'!"
          )

          subject.log_vuln(vuln)
        end
      end
    end
  end

  describe "#print_vulns" do
    let(:stdout) { StringIO.new }

    subject { command_class.new(stdout: stdout) }
    before { allow(stdout).to receive(:tty?).and_return(true) }

    let(:bright_red)        { CommandKit::Colors::ANSI::BRIGHT_RED }
    let(:bright_white)      { CommandKit::Colors::ANSI::BRIGHT_WHITE }
    let(:bold)              { CommandKit::Colors::ANSI::BOLD }
    let(:bold_bright_red)   { bold + bright_red }
    let(:bold_bright_white) { bold + bright_white }
    let(:reset_intensity)   { CommandKit::Colors::ANSI::RESET_INTENSITY }
    let(:reset_color)       { CommandKit::Colors::ANSI::RESET_COLOR }
    let(:reset)             { reset_color + reset_intensity }

    context "when given an empty Array" do
      let(:vulns) { [] }

      let(:green) { CommandKit::Colors::ANSI::GREEN }

      it "must print 'No vulnerabilities found' in green" do
        subject.print_vulns(vulns)

        expect(stdout.string).to eq(
          "#{green}No vulnerabilities found#{reset_color}#{$/}"
        )
      end
    end

    context "when given an Array of Ronin::Vulns::WebVuln objects" do
      let(:query_param1) { 'a' }
      let(:query_param2) { 'b' }
      let(:url) { URI.parse("https://example.com/page.php?#{query_param1}=foo&#{query_param2}=bar") }

      let(:vuln1) { Ronin::Vulns::SQLI.new(url, query_param: query_param1) }
      let(:vuln2) { Ronin::Vulns::SQLI.new(url, query_param: query_param2) }
      let(:vulns) { [vuln1, vuln2] }

      it "must print 'Vulnerabilities found!' in bold bright red and list the individual vulnerabilities" do
        subject.print_vulns(vulns)

        expect(stdout.string).to eq(
          [
            "#{bold_bright_red}Vulnerabilities found!#{reset}",
            '',
            "  #{bold_bright_red}SQLi#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}query param#{reset} '#{bold_bright_red}#{query_param1}#{reset}'",
            "  #{bold_bright_red}SQLi#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}query param#{reset} '#{bold_bright_red}#{query_param2}#{reset}'",
            '',
            ''
          ].join($/)
        )
      end

      context "and when given `print_curl: true`" do
        it "must print an indented example curl command for each web vulnerability" do
          subject.print_vulns(vulns, print_curl: true)

          expect(stdout.string).to eq(
            [
              "#{bold_bright_red}Vulnerabilities found!#{reset}",
              '',
              "  #{bold_bright_red}SQLi#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}query param#{reset} '#{bold_bright_red}#{query_param1}#{reset}'",
              '',
              "    #{vuln1.to_curl}",
              '',
              "  #{bold_bright_red}SQLi#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}query param#{reset} '#{bold_bright_red}#{query_param2}#{reset}'",
              '',
              "    #{vuln2.to_curl}",
              '',
              ''
            ].join($/)
          )
        end
      end

      context "and when `print_http: true` is given" do
        it "must print an indented example HTTP request for each web vulnerability" do
          subject.print_vulns(vulns, print_http: true)

          expect(stdout.string).to eq(
            [
              "#{bold_bright_red}Vulnerabilities found!#{reset}",
              '',
              "  #{bold_bright_red}SQLi#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}query param#{reset} '#{bold_bright_red}#{query_param1}#{reset}'",
              '',
              *vuln1.to_http.each_line(chomp: true).map { |line|
                "    #{line}"
              },
              '',
              "  #{bold_bright_red}SQLi#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}query param#{reset} '#{bold_bright_red}#{query_param2}#{reset}'",
              '',
              *vuln2.to_http.each_line(chomp: true).map { |line|
                "    #{line}"
              },
              '',
              ''
            ].join($/)
          )
        end
      end

      context "and when `print_curl: true` and `print_http: true` are given" do
        it "must print an indented example curl command and then an example HTTP request for each web vulnerability" do
          subject.print_vulns(vulns, print_curl: true, print_http: true)

          expect(stdout.string).to eq(
            [
              "#{bold_bright_red}Vulnerabilities found!#{reset}",
              '',
              "  #{bold_bright_red}SQLi#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}query param#{reset} '#{bold_bright_red}#{query_param1}#{reset}'",
              '',
              "    #{vuln1.to_curl}",
              '',
              *vuln1.to_http.each_line(chomp: true).map { |line|
                "    #{line}"
              },
              '',
              "  #{bold_bright_red}SQLi#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}query param#{reset} '#{bold_bright_red}#{query_param2}#{reset}'",
              '',
              "    #{vuln2.to_curl}",
              '',
              *vuln2.to_http.each_line(chomp: true).map { |line|
                "    #{line}"
              },
              '',
              ''
            ].join($/)
          )
        end
      end
    end
  end

  describe "#print_vuln" do
    let(:stdout) { StringIO.new }

    subject { command_class.new(stdout: stdout) }
    before { allow(stdout).to receive(:tty?).and_return(true) }

    let(:bright_red)        { CommandKit::Colors::ANSI::BRIGHT_RED }
    let(:bright_white)      { CommandKit::Colors::ANSI::BRIGHT_WHITE }
    let(:bold)              { CommandKit::Colors::ANSI::BOLD }
    let(:bold_bright_red)   { bold + bright_red }
    let(:bold_bright_white) { bold + bright_white }
    let(:reset_intensity)   { CommandKit::Colors::ANSI::RESET_INTENSITY }
    let(:reset_color)       { CommandKit::Colors::ANSI::RESET_COLOR     }
    let(:reset)             { reset_color + reset_intensity }

    context "when given a Ronin::Vulns::LFI object" do
      context "and the #query_param attribute is set" do
        let(:query_param) { 'id' }
        let(:vuln) { Ronin::Vulns::LFI.new(url, query_param: query_param) }

        it "must print \"LFI on <url> via query param '<query_param>'!\"" do
          subject.print_vuln(vuln)

          expect(stdout.string).to eq(
            "#{bold_bright_red}LFI#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}query param#{reset} '#{bold_bright_red}#{query_param}#{reset}'#{$/}"
          )
        end
      end

      context "and the #header_name attribute is set" do
        let(:header_name) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::LFI.new(url, header_name: header_name) }

        it "must print \"LFI on <url> via Header '<header_name>'!\"" do
          subject.print_vuln(vuln)

          expect(stdout.string).to eq(
            "#{bold_bright_red}LFI#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}Header#{reset} '#{bold_bright_red}#{header_name}#{reset}'#{$/}"
          )
        end
      end

      context "and the #cookie_param attribute is set" do
        let(:cookie_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::LFI.new(url, cookie_param: cookie_param) }

        it "must print \"LFI on <url> via Cookie param '<cookie_param>'!\"" do
          subject.print_vuln(vuln)

          expect(stdout.string).to eq(
            "#{bold_bright_red}LFI#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}Cookie param#{reset} '#{bold_bright_red}#{cookie_param}#{reset}'#{$/}"
          )
        end
      end

      context "and the #form_param attribute is set" do
        let(:form_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::LFI.new(url, form_param: form_param) }

        it "must print \"LFI on <url> via form param '<form_param>'!\"" do
          subject.print_vuln(vuln)

          expect(stdout.string).to eq(
            "#{bold_bright_red}LFI#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}form param#{reset} '#{bold_bright_red}#{form_param}#{reset}'#{$/}"
          )
        end
      end
    end

    context "when given a Ronin::Vulns::RFI object" do
      context "and the #query_param attribute is set" do
        let(:query_param) { 'id' }
        let(:vuln) { Ronin::Vulns::RFI.new(url, query_param: query_param) }

        it "must print \"RFI on <url> via query param '<query_param>'!\"" do
          subject.print_vuln(vuln)

          expect(stdout.string).to eq(
            "#{bold_bright_red}RFI#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}query param#{reset} '#{bold_bright_red}#{query_param}#{reset}'#{$/}"
          )
        end
      end

      context "and the #header_name attribute is set" do
        let(:header_name) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::RFI.new(url, header_name: header_name) }

        it "must print \"RFI on <url> via Header '<header_name>'!\"" do
          subject.print_vuln(vuln)

          expect(stdout.string).to eq(
            "#{bold_bright_red}RFI#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}Header#{reset} '#{bold_bright_red}#{header_name}#{reset}'#{$/}"
          )
        end
      end

      context "and the #cookie_param attribute is set" do
        let(:cookie_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::RFI.new(url, cookie_param: cookie_param) }

        it "must print \"RFI on <url> via Cookie param '<cookie_param>'!\"" do
          subject.print_vuln(vuln)

          expect(stdout.string).to eq(
            "#{bold_bright_red}RFI#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}Cookie param#{reset} '#{bold_bright_red}#{cookie_param}#{reset}'#{$/}"
          )
        end
      end

      context "and the #form_param attribute is set" do
        let(:form_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::RFI.new(url, form_param: form_param) }

        it "must print \"RFI on <url> via form param '<form_param>'!\"" do
          subject.print_vuln(vuln)

          expect(stdout.string).to eq(
            "#{bold_bright_red}RFI#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}form param#{reset} '#{bold_bright_red}#{form_param}#{reset}'#{$/}"
          )
        end
      end
    end

    context "when given a Ronin::Vulns::SQLI object" do
      context "and the #query_param attribute is set" do
        let(:query_param) { 'id' }
        let(:vuln) { Ronin::Vulns::SQLI.new(url, query_param: query_param) }

        it "must print \"SQLi on <url> via query param '<query_param>'!\"" do
          subject.print_vuln(vuln)

          expect(stdout.string).to eq(
            "#{bold_bright_red}SQLi#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}query param#{reset} '#{bold_bright_red}#{query_param}#{reset}'#{$/}"
          )
        end
      end

      context "and the #header_name attribute is set" do
        let(:header_name) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::SQLI.new(url, header_name: header_name) }

        it "must print \"SQLI on <url> via Header '<header_name>'!\"" do
          subject.print_vuln(vuln)

          expect(stdout.string).to eq(
            "#{bold_bright_red}SQLi#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}Header#{reset} '#{bold_bright_red}#{header_name}#{reset}'#{$/}"
          )
        end
      end

      context "and the #cookie_param attribute is set" do
        let(:cookie_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::SQLI.new(url, cookie_param: cookie_param) }

        it "must print \"SQLi on <url> via Cookie param '<cookie_param>'!\"" do
          subject.print_vuln(vuln)

          expect(stdout.string).to eq(
            "#{bold_bright_red}SQLi#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}Cookie param#{reset} '#{bold_bright_red}#{cookie_param}#{reset}'#{$/}"
          )
        end
      end

      context "and the #form_param attribute is set" do
        let(:form_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::SQLI.new(url, form_param: form_param) }

        it "must print \"SQLi on <url> via form param '<form_param>'!\"" do
          subject.print_vuln(vuln)

          expect(stdout.string).to eq(
            "#{bold_bright_red}SQLi#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}form param#{reset} '#{bold_bright_red}#{form_param}#{reset}'#{$/}"
          )
        end
      end
    end

    context "when given a Ronin::Vulns::SSTI object" do
      context "and the #query_param attribute is set" do
        let(:query_param) { 'id' }
        let(:vuln) { Ronin::Vulns::SSTI.new(url, query_param: query_param) }

        it "must print \"SSTI on <url> via query param '<query_param>'!\"" do
          subject.print_vuln(vuln)

          expect(stdout.string).to eq(
            "#{bold_bright_red}SSTI#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}query param#{reset} '#{bold_bright_red}#{query_param}#{reset}'#{$/}"
          )
        end
      end

      context "and the #header_name attribute is set" do
        let(:header_name) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::SSTI.new(url, header_name: header_name) }

        it "must print \"SSTI on <url> via Header '<header_name>'!\"" do
          subject.print_vuln(vuln)

          expect(stdout.string).to eq(
            "#{bold_bright_red}SSTI#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}Header#{reset} '#{bold_bright_red}#{header_name}#{reset}'#{$/}"
          )
        end
      end

      context "and the #cookie_param attribute is set" do
        let(:cookie_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::SSTI.new(url, cookie_param: cookie_param) }

        it "must print \"SSTI on <url> via Cookie param '<cookie_param>'!\"" do
          subject.print_vuln(vuln)

          expect(stdout.string).to eq(
            "#{bold_bright_red}SSTI#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}Cookie param#{reset} '#{bold_bright_red}#{cookie_param}#{reset}'#{$/}"
          )
        end
      end

      context "and the #form_param attribute is set" do
        let(:form_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::SSTI.new(url, form_param: form_param) }

        it "must print \"SSTI on <url> via form param '<form_param>'!\"" do
          subject.print_vuln(vuln)

          expect(stdout.string).to eq(
            "#{bold_bright_red}SSTI#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}form param#{reset} '#{bold_bright_red}#{form_param}#{reset}'#{$/}"
          )
        end
      end
    end

    context "when given a Ronin::Vulns::OpenRedirect object" do
      context "and the #query_param attribute is set" do
        let(:query_param) { 'id' }
        let(:vuln) { Ronin::Vulns::OpenRedirect.new(url, query_param: query_param) }

        it "must print \"Open Redirect on <url> via query param '<query_param>'!\"" do
          subject.print_vuln(vuln)

          expect(stdout.string).to eq(
            "#{bold_bright_red}Open Redirect#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}query param#{reset} '#{bold_bright_red}#{query_param}#{reset}'#{$/}"
          )
        end
      end

      context "and the #header_name attribute is set" do
        let(:header_name) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::OpenRedirect.new(url, header_name: header_name) }

        it "must print \"Open Redirect on <url> via Header '<header_name>'!\"" do
          subject.print_vuln(vuln)

          expect(stdout.string).to eq(
            "#{bold_bright_red}Open Redirect#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}Header#{reset} '#{bold_bright_red}#{header_name}#{reset}'#{$/}"
          )
        end
      end

      context "and the #cookie_param attribute is set" do
        let(:cookie_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::OpenRedirect.new(url, cookie_param: cookie_param) }

        it "must print \"Open Redirect on <url> via Cookie param '<cookie_param>'!\"" do
          subject.print_vuln(vuln)

          expect(stdout.string).to eq(
            "#{bold_bright_red}Open Redirect#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}Cookie param#{reset} '#{bold_bright_red}#{cookie_param}#{reset}'#{$/}"
          )
        end
      end

      context "and the #form_param attribute is set" do
        let(:form_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::OpenRedirect.new(url, form_param: form_param) }

        it "must print \"Open Redirect on <url> via form param '<form_param>'!\"" do
          subject.print_vuln(vuln)

          expect(stdout.string).to eq(
            "#{bold_bright_red}Open Redirect#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}form param#{reset} '#{bold_bright_red}#{form_param}#{reset}'#{$/}"
          )
        end
      end
    end

    context "when given a Ronin::Vulns::ReflectedXSS object" do
      context "and the #query_param attribute is set" do
        let(:query_param) { 'id' }
        let(:vuln) { Ronin::Vulns::ReflectedXSS.new(url, query_param: query_param) }

        it "must print \"reflected XSS on <url> via query param '<query_param>'!\"" do
          subject.print_vuln(vuln)

          expect(stdout.string).to eq(
            "#{bold_bright_red}reflected XSS#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}query param#{reset} '#{bold_bright_red}#{query_param}#{reset}'#{$/}"
          )
        end
      end

      context "and the #header_name attribute is set" do
        let(:header_name) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::ReflectedXSS.new(url, header_name: header_name) }

        it "must print \"reflected XSS on <url> via Header '<header_name>'!\"" do
          subject.print_vuln(vuln)

          expect(stdout.string).to eq(
            "#{bold_bright_red}reflected XSS#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}Header#{reset} '#{bold_bright_red}#{header_name}#{reset}'#{$/}"
          )
        end
      end

      context "and the #cookie_param attribute is set" do
        let(:cookie_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::ReflectedXSS.new(url, cookie_param: cookie_param) }

        it "must print \"reflected XSS on <url> via Cookie param '<cookie_param>'!\"" do
          subject.print_vuln(vuln)

          expect(stdout.string).to eq(
            "#{bold_bright_red}reflected XSS#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}Cookie param#{reset} '#{bold_bright_red}#{cookie_param}#{reset}'#{$/}"
          )
        end
      end

      context "and the #form_param attribute is set" do
        let(:form_param) { 'X-Foo' }
        let(:vuln) { Ronin::Vulns::ReflectedXSS.new(url, form_param: form_param) }

        it "must print \"reflected XSS on <url> via form param '<form_param>'!\"" do
          subject.print_vuln(vuln)

          expect(stdout.string).to eq(
            "#{bold_bright_red}reflected XSS#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}form param#{reset} '#{bold_bright_red}#{form_param}#{reset}'#{$/}"
          )
        end
      end
    end

    context "when given `print_curl: true`" do
      let(:query_param) { 'id' }
      let(:vuln) { Ronin::Vulns::SQLI.new(url, query_param: query_param) }

      it "must print an indented example curl command for the web vulnerability" do
        subject.print_vuln(vuln, print_curl: true)

        expect(stdout.string).to eq(
          [
            "#{bold_bright_red}SQLi#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}query param#{reset} '#{bold_bright_red}#{query_param}#{reset}'",
            '',
            "  #{vuln.to_curl}",
            '',
            ''
          ].join($/)
        )
      end
    end

    context "when given `print_http: true`" do
      let(:query_param) { 'id' }
      let(:vuln) { Ronin::Vulns::SQLI.new(url, query_param: query_param) }

      it "must print an indented example HTTP request for the web vulnerability" do
        subject.print_vuln(vuln, print_http: true)

        expect(stdout.string).to eq(
          [
            "#{bold_bright_red}SQLi#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}query param#{reset} '#{bold_bright_red}#{query_param}#{reset}'",
            '',
            *vuln.to_http.each_line(chomp: true).map { |line|
              "  #{line}"
            },
            '',
            ''
          ].join($/)
        )
      end
    end

    context "when given both `print_curl: true` and `print_http: true`" do
      let(:query_param) { 'id' }
      let(:vuln) { Ronin::Vulns::SQLI.new(url, query_param: query_param) }

      it "must print an indented example curl command and then an example HTTP request for the web vulnerability" do
        subject.print_vuln(vuln, print_curl: true, print_http: true)

        expect(stdout.string).to eq(
          [
            "#{bold_bright_red}SQLi#{reset} on #{bold_bright_white}#{url}#{reset} via #{bold_bright_white}query param#{reset} '#{bold_bright_red}#{query_param}#{reset}'",
            '',
            "  #{vuln.to_curl}",
            '',
            *vuln.to_http.each_line(chomp: true).map { |line|
              "  #{line}"
            },
            '',
            ''
          ].join($/)
        )
      end
    end
  end
end
