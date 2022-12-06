# frozen_string_literal: true
#
# ronin-vulns - A Ruby library for blind vulnerability testing.
#
# Copyright (c) 2007-2022 Hal Brodigan (postmodern.mod3 at gmail.com)
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
        #     -H, --header "Name: value"       Sets an additional header
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
                            desc: 'Optional test URL to try to redirect to'

          description 'Scans URL(s) for Open Redirect vulnerabilities'

          man_page 'ronin-vulns-open-redirect.1'

          #
          # Keyword arguments for `Vulns::OpenRedirect.scan` and
          # `Vulns::OpenRedirect.test`.
          #
          # @return [Hash{Symbol => Object}]
          #
          def scan_kwargs
            kwargs = super()
            kwargs[:test_url] = options[:test_url] if options[:test_url]
            return kwargs
          end

          #
          # Scans a URL for Open Redirect vulnerabiltiies.
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
          # Tests a URL for Open Redirect vulnerabiltiies.
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
