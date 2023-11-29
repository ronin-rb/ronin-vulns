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

require 'ronin/core/cli/logging'

module Ronin
  module Vulns
    class CLI
      #
      # Mixin that adds methods for logging discovered web vulnerabilities.
      #
      module Logging
        include Core::CLI::Logging

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
        # Determines the location of the web vulnerability.
        #
        # @param [WebVuln] vuln
        #
        # @return [String, nil]
        #
        # @since 0.2.0
        #
        def vuln_location(vuln)
          if vuln.query_param
            "query param '#{vuln.query_param}'"
          elsif vuln.header_name
            "Header '#{vuln.header_name}'"
          elsif vuln.cookie_param
            "Cookie param '#{vuln.cookie_param}'"
          elsif vuln.form_param
            "form param '#{vuln.form_param}'"
          end
        end

        #
        # Prints a web vulnerability.
        #
        # @param [WebVuln] vuln
        #   The web vulnerability to print.
        #
        def log_vuln(vuln)
          vuln_name = vuln_type(vuln)
          location  = vuln_location(vuln)

          if location
            log_info "Found #{vuln_name} on #{vuln.url} via #{location}!"
          else
            log_info "Found #{vuln_name} on #{vuln.url}!"
          end
        end
      end
    end
  end
end
