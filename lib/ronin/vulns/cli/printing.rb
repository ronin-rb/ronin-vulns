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

module Ronin
  module Vulns
    class CLI
      module Printing
        # Known vulnerability types and their printable names.
        VULN_TYPES = {
          open_redirect: 'Open Redirect',
          reflected_xss: 'reflected XSS',

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
          VULN_TYPES.fetch(vuln.class.vuln_type,'vulnerability')
        end

        #
        # Prints a web vulnerability.
        #
        # @param [WebVuln] vuln
        #   The web vulnerability to print.
        #
        def print_vuln(vuln)
          vuln_name = vuln_type(vuln)
          location  = if vuln.query_param
                        "query param #{vuln.query_param}"
                      elsif vuln.header_name
                        "Header #{vuln.header_name}"
                      elsif vuln.cookie_param
                        "Cookie param #{vuln.cookie_param}"
                      elsif vuln.form_param
                        "form param #{vuln.form_param}"
                      end

          if location
            puts "Found #{vuln_name} on #{vuln.url} via #{location}!"
          else
            puts "Found #{vuln_name} on #{vuln.url}!"
          end
        end
      end
    end
  end
end
