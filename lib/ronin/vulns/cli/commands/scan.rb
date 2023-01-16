# frozen_string_literal: true
#
# ronin-vulns - A Ruby library for blind vulnerability testing.
#
# Copyright (c) 2022-2023 Hal Brodigan (postmodern.mod3 at gmail.com)
#
# ronin-vulns is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ronin-vulns is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with ronin-vulns.  If not, see <https://www.gnu.org/licenses/>.
#

require 'ronin/vulns/cli/web_vuln_command'
require 'ronin/vulns/url_scanner'

module Ronin
  module Vulns
    class CLI
      module Commands
        #
        # Scans URL(s) for web vulnerabilities.
        #
        # ## Usage
        #
        #     ronin-vulns scan [options] {URL ... | --input FILE}
        #
        # ## Options
        #
        #         --first                      Only find the first vulnerability for each URL
        #     -A, --all                        Find all vulnerabilities for each URL
        #     -H, --header "Name: value"       Sets an additional header
        #     -C, --cookie COOKIE              Sets the raw Cookie header
        #     -c, --cookie-param NAME=VALUE    Sets an additional cookie param
        #     -R, --referer URL                Sets the Referer header
        #     -F, --form-param NAME=VALUE      Sets an additional form param
        #         --test-query-param NAME      Tests the URL query param name
        #         --test-header-names NAME     Tests the HTTP Header name
        #         --test-cookie-params NAME    Tests the HTTP Cookie name
        #         --test-form-params NAME      Tests the form param name
        #     -i, --input FILE                 Reads URLs from the list file
        #         --lfi-os unix|windows        Sets the OS to test for
        #         --lfi-depth COUNT            Sets the directory depth to escape up
        #         --lfi-filter-bypass null_byte|double_escape|base64|rot13|zlib
        #                                      Sets the filter bypass strategy to use
        #         --rfi-filter-bypass double-encode|suffix-escape|null-byte
        #                                      Optional filter-bypass strategy to use
        #         --rfi-script-lang asp|asp.net|coldfusion|jsp|php|perl
        #                                      Explicitly specify the scripting language to test for
        #         --rfi-test-script-url URL    Use an altnerative test script URL
        #         --sqli-escape-quote          Escapes quotation marks
        #         --sqli-escape-parens         Escapes parenthesis
        #         --sqli-terminate             Terminates the SQL expression with a --
        #         --ssti-test-expr {X*Y | X/Z | X+Y | X-Y}
        #                                      Optional numeric test to use
        #         --open-redirect-url URL      Optional test URL to try to redirect to
        #     -h, --help                       Print help information
        #
        # ## Arguments
        #
        #     [URL ...]                        The URL(s) to scan
        #
        class Scan < WebVulnCommand

          usage '[options] {URL ... | --input FILE}'

          option :lfi_os, value: {
                            type: [:unix, :windows]
                          },
                          desc: 'Sets the OS to test for'

          option :lfi_depth, value: {
                               type:  Integer,
                               usage: 'COUNT'
                             },
                             desc: 'Sets the directory depth to escape up'

          option :lfi_filter_bypass, value: {
                                       type: [
                                         :null_byte,
                                         :double_escape,
                                         :base64,
                                         :rot13,
                                         :zlib
                                       ]
                                     },
                                     desc: 'Sets the filter bypass strategy to use'

          option :rfi_filter_bypass, value: {
                                       type: {
                                         'double-encode' => :double_encode,
                                         'suffix-escape' => :suffix_escape,
                                         'null-byte'     => :null_byte
                                       },
                                     },
                                     desc: 'Optional filter-bypass strategy to use'

          option :rfi_script_lang, value: {
                                     type:  {
                                       'asp'        => :asp,
                                       'asp.net'    => :asp_net,
                                       'coldfusion' => :cold_fusion,
                                       'jsp'        => :jsp,
                                       'php'        => :php,
                                       'perl'       => :perl
                                     }
                                   },
                                   desc: 'Explicitly specify the scripting language to test for'

          option :rfi_test_script_url, value: {
                                         type:  String,
                                         usage: 'URL'
                                       },
                                       desc: 'Use an altnerative test script URL'

          option :sqli_escape_quote, desc: 'Escapes quotation marks'

          option :sqli_escape_parens, desc: 'Escapes parenthesis'

          option :sqli_terminate, desc: 'Terminates the SQL expression with a --'

          option :ssti_test_expr, value: {
                                    type: /\A\d+\s*[\*\/\+\-]\s*\d+\z/,
                                    usage: '{X*Y | X/Z | X+Y | X-Y}'
                                  },
                                  desc: 'Optional numeric test to use' do |expr|
                                    @ssti_test_expr = Vulns::SSTI::TestExpression.parse(expr)
                                  end

          option :open_redirect_url, value: {
                                       type:  String,
                                       usage: 'URL'
                                     },
                                     desc: 'Optional test URL to try to redirect to'

          description 'Scans URL(s) for web vulnerabilities'

          man_page 'ronin-vulns-scan.1'

          #
          # Keyword arguments which will be passed to {URLScanner.scan} or
          # {URLScanner.test} via the `lfi:` keyword.
          #
          # @return [Hash{Symbol => Object}]
          #
          def lfi_kwargs
            kwargs = {}

            kwargs[:os]    = options[:lfi_os]    if options[:lfi_os]
            kwargs[:depth] = options[:lfi_depth] if options[:lfi_depth]

            if options[:lfi_filter_bypass]
              kwargs[:filter_bypass] = options[:lfi_filter_bypass]
            end

            return kwargs
          end

          #
          # Keyword arguments which will be passed to {URLScanner.scan} or
          # {URLScanner.test} via the `rfi:` keyword.
          #
          # @return [Hash{Symbol => Object}]
          #
          def rfi_kwargs
            kwargs = {}

            if options[:rfi_filter_bypass]
              kwargs[:filter_bypass] = options[:rfi_filter_bypass]
            end

            if options[:rfi_script_lang]
              kwargs[:script_lang] = options[:rfi_script_lang]
            end

            if options[:rfi_test_script_url]
              kwargs[:test_script_url] = options[:rfi_test_script_url]
            end

            return kwargs
          end

          #
          # Keyword arguments which will be passed to {URLScanner.scan} or
          # {URLScanner.test} via the `sqli:` keyword.
          #
          # @return [Hash{Symbol => Object}]
          #
          def sqli_kwargs
            kwargs = {}

            if options[:sqli_escape_quote]
              kwargs[:escape_quote] = options[:sqli_escape_quote]
            end

            if options[:sqli_escape_parens]
              kwargs[:escape_parens] = options[:sqli_escape_parens]
            end

            if options[:sqli_terminate]
              kwargs[:terminate] = options[:sqli_terminate]
            end

            return kwargs
          end

          #
          # Keyword arguments which will be passed to {URLScanner.scan} or
          # {URLScanner.test} via the `ssti:` keyword.
          #
          # @return [Hash{Symbol => Object}]
          #
          def ssti_kwargs
            kwargs = {}

            kwargs[:test_expr] = @ssti_test_expr if @ssti_test_expr

            return kwargs
          end

          #
          # Keyword arguments which will be passed to {URLScanner.scan} or
          # {URLScanner.test} via the `open_redirect:` keyword.
          #
          # @return [Hash{Symbol => Object}]
          #
          def open_redirect_kwargs
            kwargs = {}

            if options[:open_redirect_url]
              kwargs[:test_url] = options[:open_redirect_url]
            end

            return kwargs
          end

          #
          # Keyword arguments which will be passed to {URLScanner.scan} or
          # {URLScanner.test} via the `reflected_xss:` keyword.
          #
          # @return [Hash{Symbol => Object}]
          #
          def reflected_xss_kwargs
            {}
          end

          #
          # Keyword arguments for `Vulns::URLScanner.scan` and
          # `Vulns::URLScanner.test`.
          #
          # @return [Hash{Symbol => Object}]
          #
          def scan_kwargs
            kwargs = super()

            kwargs[:lfi]  = lfi_kwargs
            kwargs[:rfi]  = rfi_kwargs
            kwargs[:sqli] = sqli_kwargs
            kwargs[:ssti] = ssti_kwargs
            kwargs[:open_redirect] = open_redirect_kwargs
            kwargs[:reflected_xss] = reflected_xss_kwargs

            return kwargs
          end

          #
          # Scans a URL for all web vulnerabilities.
          #
          # @param [String] url
          #   The URL to scan.
          #
          # @yield [vuln]
          #   The given block will be passed each discovered web vulnerability.
          #
          # @yieldparam [Vulns::LFI,
          #          Vulns::RFI,
          #          Vulns::SQLI,
          #          Vulns::SSTI,
          #          Vulns::OpenRedirect,
          #          Vulns::ReflectedXSS] vuln
          #   A LFI vulnerability discovered on the URL.
          #
          def scan_url(url,&block)
            Vulns::URLScanner.scan(url,**scan_kwargs,&block)
          end

          #
          # Tests a URL for any web vulnerabilities.
          #
          # @param [String] url
          #   The URL to test.
          #
          # @return [Vulns::LFI,
          #          Vulns::RFI,
          #          Vulns::SQLI,
          #          Vulns::SSTI,
          #          Vulns::OpenRedirect,
          #          Vulns::ReflectedXSS, nil]
          #   The first web vulnerability discovered on the URL.
          #
          def test_url(url,&block)
            Vulns::URLScanner.test(url,**scan_kwargs)
          end

        end
      end
    end
  end
end
