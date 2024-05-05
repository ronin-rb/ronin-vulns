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
require 'ronin/vulns/ssti'

module Ronin
  module Vulns
    class CLI
      module Commands
        #
        # Scans URL(s) for Server Side Template Injection (SSTI)
        # vulnerabilities.
        #
        # ## Usage
        #
        #     ronin-vulns ssti [options] {URL ... | --input FILE}
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
        #         --test-all-form-params       Test all form param names
        #     -i, --input FILE                 Reads URLs from the list file
        #     -T {X*Y | X/Z | X+Y | X-Y},      Optional numeric test to use
        #         --test-expr
        #     -h, --help                       Print help information
        #
        # ## Arguments
        #
        #     [URL ...]                        The URL(s) to scan
        #
        class Ssti < WebVulnCommand

          usage '[options] {URL ... | --input FILE}'

          option :test_expr, short: '-T',
                             value: {
                               type: %r{\A\d+\s*[\*/\+\-]\s*\d+\z},
                               usage: '{X*Y | X/Z | X+Y | X-Y}'
                             },
                             desc: 'Optional numeric test to use' do |expr|
                               scan_kwargs[:test_expr] = Vulns::SSTI::TestExpression.parse(expr)
                             end

          description 'Scans URL(s) for Server Side Template Injection (SSTI) vulnerabilities'

          man_page 'ronin-vulns-ssti.1'

          #
          # Scans a URL for SSTI vulnerabilities.
          #
          # @param [String] url
          #   The URL to scan.
          #
          # @yield [vuln]
          #   The given block will be passed each discovered SSTI vulnerability.
          #
          # @yieldparam [Vulns::SSTI] vuln
          #   A SSTI vulnerability discovered on the URL.
          #
          def scan_url(url,&block)
            Vulns::SSTI.scan(url,**scan_kwargs,&block)
          end

          #
          # Tests a URL for SSTI vulnerabilities.
          #
          # @param [String] url
          #   The URL to test.
          #
          # @return [Vulns::SSTI, nil]
          #   The first SSTI vulnerability discovered on the URL.
          #
          def test_url(url,&block)
            Vulns::SSTI.test(url,**scan_kwargs)
          end

        end
      end
    end
  end
end
