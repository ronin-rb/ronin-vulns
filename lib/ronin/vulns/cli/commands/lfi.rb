# frozen_string_literal: true
#
# ronin-vulns - A Ruby library for blind vulnerability testing.
#
# Copyright (c) 2022-2026 Hal Brodigan (postmodern.mod3 at gmail.com)
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

require_relative '../web_vuln_command'
require_relative '../../lfi'

module Ronin
  module Vulns
    class CLI
      module Commands
        #
        # Scans URL(s) for Local File Inclusion (LFI) vulnerabilities
        #
        # ## Usage
        #
        #     ronin-vulns lfi [options] {URL ... | --input FILE}
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
        #         --test-all-form-params       Test all form param names
        #     -i, --input FILE                 Reads URLs from the list file
        #     -O, --os unix|windows            Sets the OS to test for
        #     -D, --depth COUNT                Sets the directory depth to escape up
        #     -B null-byte|double-escape|base64|rot13|zlib,
        #         --filter-bypass              Sets the filter bypass strategy to use
        #     -h, --help                       Print help information
        #
        # ## Arguments
        #
        #     [URL ...]                        The URL(s) to scan
        #
        class Lfi < WebVulnCommand

          usage '[options] {URL ... | --input FILE}'

          option :os, short: '-O',
                      value: {
                        type: [:unix, :windows]
                      },
                      desc: 'Sets the OS to test for' do |os|
                        scan_kwargs[:os] = os
                      end

          option :depth, short: '-D',
                         value: {
                           type:  Integer,
                           usage: 'COUNT'
                         },
                         desc: 'Sets the directory depth to escape up' do |depth|
                           scan_kwargs[:depth] = depth
                         end

          option :filter_bypass, short: '-B',
                                 value: {
                                   type: {
                                     'null-byte'     => :null_byte,
                                     'double-escape' => :double_escape,
                                     'base64'        => :base64,
                                     'rot13'         => :rot13,
                                     'zlib'          => :zlib
                                   }
                                 },
                                 desc: 'Sets the filter bypass strategy to use' do |filter_bypass|
                                   scan_kwargs[:filter_bypass] = filter_bypass
                                 end

          description 'Scans URL(s) for Local File Inclusion (LFI) vulnerabilities'

          man_page 'ronin-vulns-lfi.1'

          #
          # Scans a URL for LFI vulnerabilities.
          #
          # @param [String] url
          #   The URL to scan.
          #
          # @yield [vuln]
          #   The given block will be passed each discovered LFI vulnerability.
          #
          # @yieldparam [Vulns::LFI] vuln
          #   A LFI vulnerability discovered on the URL.
          #
          def scan_url(url,&block)
            Vulns::LFI.scan(url,**scan_kwargs,&block)
          end

          #
          # Tests a URL for LFI vulnerabilities.
          #
          # @param [String] url
          #   The URL to test.
          #
          # @return [Vulns::LFI, nil]
          #   The first LFI vulnerability discovered on the URL.
          #
          def test_url(url,&block)
            Vulns::LFI.test(url,**scan_kwargs)
          end

        end
      end
    end
  end
end
