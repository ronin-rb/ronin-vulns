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
require_relative '../../command_injection'

module Ronin
  module Vulns
    class CLI
      module Commands
        #
        # Scans URL(s) for Command Injection vulnerabilities.
        #
        # ## Usage
        #
        #     ronin-vulns command-injection [options] {URL ... | --input FILE}
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
        #     -Q, --escape-quote CHAR          The string quotation character to use to escape the command
        #     -O, --escape-operator CHAR       The command operator character to use to escape the command
        #     -T, --terminator CHAR            The command termination character to use
        #     -h, --help                       Print help information
        #
        # ## Arguments
        #
        #     [URL ...]                        The URL(s) to scan
        #
        # @since 0.2.0
        #
        class CommandInjection < WebVulnCommand

          usage '[options] {URL ... | --input FILE}'

          # Regex for matching a single `CHAR` option value.
          CHAR_REGEX = /./

          option :escape_quote, short: '-Q',
                                value: {
                                  type:  CHAR_REGEX,
                                  usage: 'CHAR'
                                },
                                desc:  'The string quotation character to use to escape the command'

          option :escape_operator, short: '-O',
                                   value: {
                                     type:  CHAR_REGEX,
                                     usage: 'CHAR'
                                   },
                                   desc:  'The command operator character to use to escape the command'

          option :terminator, short: '-T',
                              value: {
                                type: CHAR_REGEX,
                                usage: 'CHAR'
                              },
                              desc:  'The command termination character to use'

          description 'Scans URL(s) for Command Injection vulnerabilities'

          man_page 'ronin-vulns-command-injection.1'

          #
          # Keyword arguments for `Vulns::CommandInjection.scan` and
          # `Vulns::CommandInjection.test`.
          #
          # @return [Hash{Symbol => Object}]
          #
          def scan_kwargs
            kwargs = super()

            if options[:escape_quote]
              kwargs[:escape_quote] = options[:escape_quote]
            end

            if options[:escape_operator]
              kwargs[:escape_operator] = options[:escape_operator]
            end

            if options[:terminator]
              kwargs[:terminator] = options[:terminator]
            end

            return kwargs
          end

          #
          # Scans a URL for Command Injection vulnerabilities.
          #
          # @param [String] url
          #   The URL to scan.
          #
          # @yield [vuln]
          #   The given block will be passed each discovered Command Injection
          #   vulnerability.
          #
          # @yieldparam [Vulns::CommandInjection] vuln
          #   A Command Injection vulnerability discovered on the URL.
          #
          def scan_url(url,&block)
            Vulns::CommandInjection.scan(url,**scan_kwargs,&block)
          end

          #
          # Tests a URL for Command Injection vulnerabilities.
          #
          # @param [String] url
          #   The URL to test.
          #
          # @return [Vulns::CommandInjection, nil]
          #   The first Command Injection vulnerability discovered on the URL.
          #
          def test_url(url,&block)
            Vulns::CommandInjection.test(url,**scan_kwargs)
          end

        end
      end
    end
  end
end
