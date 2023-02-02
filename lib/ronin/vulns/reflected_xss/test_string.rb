# frozen_string_literal: true
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
    class ReflectedXSS < WebVuln
      #
      # A test string of characters to determine which special characters are
      # escaped/filtered and which are passed through.
      #
      # @api private
      #
      class TestString

        # The test string.
        #
        # @return [String]
        attr_reader :string

        # The test regexp to determine which special characters were
        # escaped/filtered and which were passed through unescaped.
        #
        # @return [Regexp]
        attr_reader :regexp

        #
        # Initializes the test string.
        #
        # @param [String] string
        #   The test string.
        #
        # @param [Regexp] regexp
        #   The test regexp to determine which special characters were
        #   escaped/filtered and which were passed through unescaped.
        #
        def initialize(string,regexp)
          @string = string
          @regexp = regexp
        end

        # Special characters and their common escaped equivalents.
        ESCAPED_CHARS = {
          "'" => ['%27', '&#39;', "\\'"],
          '"' => ['%22', '&quot;', "\\\""],
          ' ' => ['+', '%20', '&nbsp;'],
          '=' => ['%3D'],
          '/' => ['%2F'],
          '<' => ['%3C', '&lt;'],
          '>' => ['%3E', '&gt;'],
          '&' => ['%26', '&amp;'],
        }

        #
        # Builds a test string from a mapping of characters and their HTML
        # escaped equivalents.
        #
        # @param [String] chars
        #   The characters for the test string.
        #
        # @return [TestString]
        #   The built test string.
        #
        def self.build(chars)
          string = String.new
          regexp = String.new

          chars.each_char do |char|
            string << char

            regexp << "(?:(#{Regexp.escape(char)})"

            if (escaped_chars = ESCAPED_CHARS[char])
              escaped_chars.each do |string|
                regexp << "|#{Regexp.escape(string)}"
              end
            end

            regexp << ')?'
          end

          return new(string,Regexp.new(regexp))
        end

        #
        # Wraps the test string with a prefix and suffix.
        #
        # @param [String] prefix
        #   The prefix string to prepend to the test string.
        #
        # @param [String] suffix
        #   The suffix string to append to the test string.
        #
        # @return [TestString]
        #   The new test string with the prefix and suffix.
        #
        def wrap(prefix,suffix)
          self.class.new(
            "#{prefix}#{@string}#{suffix}",
            /#{Regexp.escape(prefix)}#{@regexp}#{Regexp.escape(suffix)}/
          )
        end

        #
        # Matches the response body against {#regexp}.
        #
        # @param [String] body
        #   The response body to try matching.
        #
        # @return [MatchData, nil]
        #   The match data or `nil` if the body did not match {#regexp}.
        #
        def match(body)
          body.match(@regexp)
        end

        #
        # Converts the test string to a String.
        #
        # @return [String]
        #   The {#string}.
        #
        def to_s
          @string
        end

      end
    end
  end
end
