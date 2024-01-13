# frozen_string_literal: true
#
# ronin-vulns - A Ruby library for blind vulnerability testing.
#
# Copyright (c) 2022-2024 Hal Brodigan (postmodern.mod3 at gmail.com)
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
require 'ronin/vulns/reflected_xss/test_string'
require 'ronin/vulns/reflected_xss/context'

require 'set'

module Ronin
  module Vulns
    #
    # Represents a (Reflected) Cross Site Scripting (XSS) vulnerability.
    #
    # ## Features
    #
    # * Tests a URL with just one HTTP request (per param).
    # * Tests which HTML special characters are allowed.
    # * Identifies the context, tag name, and/or attribute name of the XSS.
    # * Determines viability of XSS based on the context.
    # * Includes random data in the test values.
    #
    class ReflectedXSS < WebVuln

      # The characters that are allowed and will not be escaped or filtered.
      #
      # @return [Set<String>, nil]
      attr_reader :allowed_chars

      # The context the XSS occurred in.
      #
      # @return [Context, nil]
      attr_reader :context

      #
      # Tests the test string by sending an HTTP request with the test string
      # embedded.
      #
      # @param [TestString] test_string
      #
      # @yield [body, match]
      #   If the response was `text/html` and the test string appears (at least
      #   partially) in the response body, the response body and match data will
      #   be yielded.
      #
      # @yieldparam [String] body
      #   The response body.
      #
      # @yieldparam [MatchData] match
      #   The matched data for the test string.
      #
      # @api private
      #
      def test_string(test_string)
        test_string = test_string.wrap(random_value,random_value)

        response     = exploit("#{original_value}#{test_string}")
        content_type = response.content_type
        body         = response.body

        if content_type && content_type.include?('text/html')
          if (match = test_string.match(body))
            yield body, match
          end
        end
      end

      #
      # Tests whether characters in the test string will be escaped/filtered or
      # passed through and updates {#allowed_chars}.
      #
      # @param [TestString] test_string
      #   The test string to send.
      #
      # @yield [body, match]
      #   If a block is given, it will be passed the response body and the
      #   regular expression match data, if the response contains the test
      #   string.
      #
      # @yieldparam [String] body
      #   The response body.
      #
      # @yieldparam [MatchData] match
      #   The matched data for the test string.
      #
      # @api private
      #
      def test_chars(test_string)
        test_string(test_string) do |body,match|
          @allowed_chars ||= Set.new
          @allowed_chars.merge(match.captures.compact)

          yield body, match if block_given?
        end
      end

      # HTML special characters to test.
      HTML_TEST_STRING = TestString.build("'\"= /><")

      #
      # Tests which HTML characters are accepted or escaped/filtered.
      #
      # @yield [body, match]
      #   If a block is given, it will be passed the response body and the
      #   regular expression match data, if the response contains the test
      #   string.
      #
      # @yieldparam [String] body
      #   The response body.
      #
      # @yieldparam [MatchData] match
      #   The matched data for the test string.
      #
      # @api private
      #
      def test_html_chars(&block)
        test_chars(HTML_TEST_STRING,&block)
      end

      #
      # Tests whether the URL is vulnerable to (Reflected) Cross Site Scripting
      # (XSS).
      #
      # @return [Boolean]
      #   Indicates whether the URL is vulnerable to (Reflected) Cross Site
      #   Scripting (XSS).
      #
      # @note
      #   If the URL is vulnerable, {#allowed_chars} and {#context} will be set.
      #
      def vulnerable?
        # test HTML special characters
        test_html_chars do |body,match|
          xss_index = match.begin(0)

          # determine the contents which the XSS occurs
          if (@context = Context.identify(body,xss_index))
            # determine whether enough special HTML characters are allowed to
            # escape the context which the XSS occurs.
            return @context.viable?(@allowed_chars)
          end
        end

        return false
      end

      #
      # Returns the type or kind of vulnerability.
      #
      # @return [Symbol]
      #
      # @note
      #   This is used internally to map an vulnerability class to a printable
      #   type.
      #
      # @api private
      #
      # @abstract
      #
      def self.vuln_type
        :reflected_xss
      end

    end
  end
end
