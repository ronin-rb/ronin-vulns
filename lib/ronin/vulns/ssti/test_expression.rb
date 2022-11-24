#
# ronin-vulns - A Ruby library for blind vulnerability testing.
#
# Copyright (c) 2022 Hal Brodigan (postmodern.mod3 at gmail.com)
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

require 'ronin/vulns/web_vuln'

module Ronin
  module Vulns
    #
    # Represents a Server Side Template Injection (SSTI) vulnerability.
    #
    class SSTI < WebVuln
      #
      # Represents a expression to test SSTI with (ex: `7*7`).
      #
      class TestExpression

        # The expression string.
        #
        # @return [String]
        attr_reader :string

        # The expected result of the string.
        #
        # @return [String]
        attr_reader :result

        #
        # Initializes the test expression.
        #
        # @param [String] string
        #   The expression string.
        #
        # @param [String] result
        #   The expected result of the expression.
        #
        def initialize(string,result)
          @string = string
          @result = result
        end

        #
        # The test expression as a String.
        #
        # @return [String]
        #   The {#string} value.
        #
        def to_s
          @string
        end

      end
    end
  end
end
