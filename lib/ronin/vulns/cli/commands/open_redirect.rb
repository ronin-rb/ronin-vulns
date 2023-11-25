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
require 'ronin/vulns/open_redirect'

module Ronin
  module Vulns
    class CLI
      module Commands
        #
        # Scans URL(s) for Open Redirect vulnerabilities.
        #
        # ## Usage
        #
        #     ronin-vulns open-redirect [options] {URL ... | --input FILE}
        #
        # ## Options
        #
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
        #     -T, --test-url URL               Optional test URL to try to redirect to
        #     -h, --help                       Print help information
        #
        # ## Arguments
        #
        #     [URL ...]                        The URL(s) to scan
        #
        class OpenRedirect < WebVulnCommand

          usage '[options] {URL ... | --input FILE}'

          option :test_url, short: '-T',
                            value: {
                              type:  String,
                              usage: 'URL'
                            },
                            desc: 'Optional test URL to try to redirect to' do |test_url|
                              scan_kwargs[:test_url] = test_url
                            end

          description 'Scans URL(s) for Open Redirect vulnerabilities'

          man_page 'ronin-vulns-open-redirect.1'

          #
          # Scans a URL for Open Redirect vulnerabilities.
          #
          # @param [String] url
          #   The URL to scan.
          #
          # @yield [vuln]
          #   The given block will be passed each discovered OpenRedirect
          #   vulnerability.
          #
          # @yieldparam [Vulns::OpenRedirect] vuln
          #   A OpenRedirect vulnerability discovered on the URL.
          #
          def scan_url(url,&block)
            Vulns::OpenRedirect.scan(url,**scan_kwargs,&block)
          end

          #
          # Tests a URL for Open Redirect vulnerabilities.
          #
          # @param [String] url
          #   The URL to test.
          #
          # @return [Vulns::OpenRedirect, nil]
          #   The first Open Redirect vulnerability discovered on the URL.
          #
          def test_url(url,&block)
            Vulns::OpenRedirect.test(url,**scan_kwargs)
          end

        end
      end
    end
  end
end
