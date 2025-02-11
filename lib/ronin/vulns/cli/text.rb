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

module Ronin
  module Vulns
    class CLI
      #
      # Methods for generating displayable text.
      #
      # @since 0.3.0
      #
      module Text
        # Known vulnerability types and their display names.
        VULN_TYPE_NAMES = {
          command_injection: 'Command Injection',
          open_redirect:     'Open Redirect',
          reflected_xss:     'reflected XSS',

          lfi:  'LFI',
          rfi:  'RFI',
          sqli: 'SQLi',
          ssti: 'SSTI'
        }

        #
        # Returns the vulnerability type display name for the vulnerability
        # object.
        #
        # @param [Vuln] vuln
        #
        # @return [String]
        #
        def vuln_type_name(vuln)
          VULN_TYPE_NAMES.fetch(vuln.class.vuln_type)
        end

        #
        # Determines the param type display name that the web vulnerability
        # occurs in.
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
      end
    end
  end
end
