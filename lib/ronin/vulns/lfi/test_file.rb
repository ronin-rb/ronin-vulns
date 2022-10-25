#
# ronin-vuln - A Ruby library to blind vulnerability testing.
#
# Copyright (c) 2022 Hal Brodigan (postmodern.mod3 at gmail.com)
#
# ronin-vuln is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ronin-vuln is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with ronin-vuln.  If not, see <https://www.gnu.org/licenses/>.
#

require 'ronin/vulns/web_vuln'

module Ronin
  module Vulns
    class LFI < WebVuln
      #
      # Represents a single Local File Inclusion (LFI) test for a given file
      # path and a regexp that matches the file.
      #
      # @api private
      #
      class TestFile

        # The path of the file to attempt including.
        #
        # @return [String]
        attr_reader :path

        # The regexp to identify a successful Local File Inclusion (LFI)
        # of the {#path}.
        #
        # @return [Regexp]
        attr_reader :regexp

        #
        # Initializes the Local File Inclusion (LFI) test.
        #
        # @param [String] path
        #   The path to attempt including.
        #
        # @param [Regexp] regexp
        #   The regexp to identify a successful Local File Inclusion (LFI)
        #   of the {#path}.
        #
        def initialize(path,regexp)
          @path   = path
          @regexp = regexp
        end

        #
        # Tests whether the file was successfully included into the response
        # body.
        #
        # @param [String] response_body
        #   The HTTP response body.
        #
        # @return [MatchData, nil]
        #   The match data if the {#regexp} is found within the response body.
        #
        def match(response_body)
          response_body.match(@regexp)
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
