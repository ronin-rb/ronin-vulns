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

require 'ronin/vulns/web_vuln'

module Ronin
  module Vulns
    class SQLI < WebVuln
      #
      # Represents a collection of patterns for SQL error messages for a
      # particular database.
      #
      # @api private
      #
      class ErrorPattern

        # The combined error message regexp.
        #
        # @return [Regexp]
        attr_reader :regexp

        #
        # Initializes the error pattern.
        #
        # @param [Regexp] regexp
        #   The combined of regular expression.
        #
        def initialize(regexp)
          @regexp = regexp
        end

        #
        # Creates an error pattern from multiple different regexps.
        #
        # @param [Array<Regexp>] regexps
        #   The collection of regular expressions.
        #
        def self.[](*regexps)
          new(Regexp.union(regexps))
        end

        #
        # Tests whether the response body contains a SQL error.
        #
        # @param [String] response_body
        #   The HTTP response body.
        #
        # @return [MatchData, nil]
        #   The match data if the {#regexp} is found within the response body.
        #
        def match(response_body)
          @regexp.match(response_body)
        end

        #
        # Tests whether the file was successfully included into the response
        # body.
        #
        # @param [String] response_body
        #   The HTTP response body.
        #
        # @return [Integer, nil]
        #   Indicates whether the {#regexp} was found in the response body.
        #
        def =~(response_body)
          response_body =~ @regexp
        end

      end
    end
  end
end
