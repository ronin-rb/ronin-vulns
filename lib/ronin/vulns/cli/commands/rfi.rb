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
require 'ronin/vulns/rfi'

module Ronin
  module Vulns
    class CLI
      module Commands
        #
        # Scans URL(s) for Remote File Inclusion (RFI) vulnerabilities.
        #
        # ## Usage
        #
        #     ronin-vulns rfi [options] {URL ... | --input FILE}
        #
        # ## Options
        #
        #         --db NAME                    The database to connect to (Default: default)
        #         --db-uri URI                 The database URI to connect to
        #         --db-file PATH               The sqlite3 database file to use
        #         --import                     Imports discovered vulnerabilities into the database
        #         --first                      Only find the first vulnerability for each URL
        #     -A, --all                        Find all vulnerabilities for each URL
        #         --print-curl                 Also prints an example curl command for each vulnerability
        #         --print-http                 Also prints an example HTTP request for each vulnerability
        #     -M COPY|DELETE|GET|HEAD|LOCK|MKCOL|MOVE|OPTIONS|PATCH|POST|PROPFIND|PROPPATCH|PUT|TRACE|UNLOCK,
        #         --request-method             The HTTP request method to use
        #     -H, --header "Name: value"       Sets an additional header
        #     -U, --user-agent-string STRING   Sets the User-Agent header
        #     -u chrome-linux|chrome-macos|chrome-windows|chrome-iphone|chrome-ipad|chrome-android|firefox-linux|firefox-macos|firefox-windows|firefox-iphone|firefox-ipad|firefox-android|safari-macos|safari-iphone|safari-ipad|edge,
        #         --user-agent                 Sets the User-Agent to use
        #     -C, --cookie COOKIE              Sets the raw Cookie header
        #     -c, --cookie-param NAME=VALUE    Sets an additional cookie param
        #     -R, --referer URL                Sets the Referer header
        #     -F, --form-param NAME=VALUE      Sets an additional form param
        #         --test-query-param NAME      Tests the URL query param name
        #         --test-all-query-params      Test all URL query param names
        #         --test-header-name NAME      Tests the HTTP Header name
        #         --test-cookie-param NAME     Tests the HTTP Cookie name
        #         --test-all-cookie-params     Test all Cookie param names
        #         --test-form-param NAME       Tests the form param name
        #     -i, --input FILE                 Reads URLs from the list file
        #     -B double-encode|suffix-escape|null-byte,
        #         --filter-bypass              Optional filter-bypass strategy to use
        #     -S asp|asp.net|coldfusion|jsp|php|perl,
        #         --script-lang                Explicitly specify the scripting language to test for
        #     -T, --test-script-url URL        Use an alternative test script URL
        #     -h, --help                       Print help information
        #
        # ## Arguments
        #
        #     [URL ...]                        The URL(s) to scan
        #
        class Rfi < WebVulnCommand

          usage '[options] {URL ... | --input FILE}'

          option :filter_bypass, short: '-B',
                                 value: {
                                   type: {
                                     'double-encode' => :double_encode,
                                     'suffix-escape' => :suffix_escape,
                                     'null-byte'     => :null_byte
                                   }
                                 },
                                 desc: 'Optional filter-bypass strategy to use' do |filter_bypass|
                                   scan_kwargs[:filter_bypass] = filter_bypass
                                 end

          option :script_lang, short: '-S',
                               value: {
                                 type:  {
                                   'asp'        => :asp,
                                   'asp.net'    => :asp_net,
                                   'coldfusion' => :cold_fusion,
                                   'jsp'        => :jsp,
                                   'php'        => :php,
                                   'perl'       => :perl
                                 }
                               },
                               desc: 'Explicitly specify the scripting language to test for' do |script_lang|
                                 scan_kwargs[:script_lang] = script_lang
                               end

          option :test_script_url, short: '-T',
                                   value: {
                                     type:  String,
                                     usage: 'URL'
                                   },
                                   desc: 'Use an alternative test script URL' do |test_script_url|
                                     scan_kwargs[:test_script_url] = test_script_url
                                   end

          description 'Scans URL(s) for Remote File Inclusion (RFI) vulnerabilities'

          man_page 'ronin-vulns-rfi.1'

          #
          # Scans a URL for RFI vulnerabilities.
          #
          # @param [String] url
          #   The URL to scan.
          #
          # @yield [vuln]
          #   The given block will be passed each discovered RFI vulnerability.
          #
          # @yieldparam [Vulns::RFI] vuln
          #   A RFI vulnerability discovered on the URL.
          #
          def scan_url(url,&block)
            Vulns::RFI.scan(url,**scan_kwargs,&block)
          end

          #
          # Tests a URL for RFI vulnerabilities.
          #
          # @param [String] url
          #   The URL to test.
          #
          # @return [Vulns::RFI, nil]
          #   The first RFI vulnerability discovered on the URL.
          #
          def test_url(url,&block)
            Vulns::RFI.test(url,**scan_kwargs)
          end

        end
      end
    end
  end
end
