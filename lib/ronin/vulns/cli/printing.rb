# frozen_string_literal: true
#
# ronin-vulns - A Ruby library for blind vulnerability testing.
#
# Copyright (c) 2022-2025 Hal Brodigan (postmodern.mod3 at gmail.com)
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

require 'ronin/core/cli/logging'

require 'command_kit/printing/indent'

module Ronin
  module Vulns
    class CLI
      #
      # Mixin that adds methods for logging and printing discovered web
      # vulnerabilities.
      #
      # @since 0.2.0
      #
      module Printing
        include Core::CLI::Logging
        include CommandKit::Printing::Indent

        # Known vulnerability types and their printable names.
        VULN_TYPES = {
          command_injection: 'Command Injection',
          open_redirect:     'Open Redirect',
          reflected_xss:     'reflected XSS',

          lfi:  'LFI',
          rfi:  'RFI',
          sqli: 'SQLi',
          ssti: 'SSTI'
        }

        #
        # Returns the printable vulnerability type for the vulnerability object.
        #
        # @param [Vuln] vuln
        #
        # @return [String]
        #
        def vuln_type(vuln)
          VULN_TYPES.fetch(vuln.class.vuln_type)
        end

        #
        # Determines the param type that the web vulnerability occurs in.
        #
        # @param [WebVuln] vuln
        #
        # @return [String, nil]
        #
        def vuln_param_type(vuln)
          if    vuln.query_param  then 'query param'
          elsif vuln.header_name  then 'Header'
          elsif vuln.cookie_param then 'Cookie param'
          elsif vuln.form_param   then 'form param'
          end
        end

        #
        # Determines the param name that the web vulnerability occurs in.
        #
        # @param [WebVuln] vuln
        #
        # @return [String, nil]
        #
        def vuln_param_name(vuln)
          if    vuln.query_param  then vuln.query_param
          elsif vuln.header_name  then vuln.header_name
          elsif vuln.cookie_param then vuln.cookie_param
          elsif vuln.form_param   then vuln.form_param
          end
        end

        #
        # Prints a log message about a newly discovered web vulnerability.
        #
        # @param [WebVuln] vuln
        #   The web vulnerability to log.
        #
        def log_vuln(vuln)
          vuln_type  = vuln_type(vuln)
          param_type = vuln_param_type(vuln)
          param_name = vuln_param_name(vuln)

          if (param_type && param_name)
            log_warn "Found #{vuln_type} on #{vuln.url} via #{param_type} '#{param_name}'!"
          else
            log_warn "Found #{vuln_type} on #{vuln.url}!"
          end
        end

        #
        # Prints detailed information about a discovered web vulnerability.
        #
        # @param [WebVuln] vuln
        #   The web vulnerability to log.
        #
        # @param [Boolean] print_curl
        #   Prints an example `curl` command to trigger the web vulnerability.
        #
        # @param [Boolean] print_http
        #   Prints an example HTTP request to trigger the web vulnerability.
        #
        # @since 0.2.0
        #
        def print_vuln(vuln, print_curl: false, print_http: false)
          vuln_type  = vuln_type(vuln)
          param_type = vuln_param_type(vuln)
          param_name = vuln_param_name(vuln)

          if (param_type && param_name)
            puts "#{colors.bold(colors.bright_red(vuln_type))} on #{colors.bold(colors.bright_white(vuln.url))} via #{colors.bold(colors.bright_white(param_type))} '#{colors.bold(colors.bright_red(param_name))}'"
          else
            puts "#{colors.bold(colors.red(vuln_type))} on #{colors.bold(colors.bright_white(vuln.url))}"
          end

          if print_curl || print_http
            puts

            if print_curl
              puts "  #{vuln.to_curl}"
              puts
            end

            if print_http
              vuln.to_http.each_line(chomp: true) do |line|
                puts "  #{line}"
              end
              puts
            end
          end
        end

        #
        # Print a summary of all web vulnerabilities found.
        #
        # @param [Array<WebVuln>] vulns
        #   The discovered web vulnerabilities.
        #
        # @param [Boolean] print_curl
        #   Prints an example `curl` command to trigger the web vulnerability.
        #
        # @param [Boolean] print_http
        #   Prints an example HTTP request to trigger the web vulnerability.
        #
        # @since 0.2.0
        #
        def print_vulns(vulns, print_curl: false, print_http: false)
          if vulns.empty?
            puts colors.green("No vulnerabilities found")
          else
            puts colors.bold(colors.bright_red('Vulnerabilities found!'))
            puts

            indent do
              vulns.each do |vuln|
                print_vuln(vuln, print_curl: print_curl,
                                 print_http: print_http)
              end
            end
            puts unless (print_curl || print_http)
          end
        end
      end
    end
  end
end
