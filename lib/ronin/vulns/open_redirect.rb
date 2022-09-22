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

require 'ronin/vulns/web'

require 'chars'
require 'cgi'

module Ronin
  module Vulns
    #
    # Represents an Open Redirect vulnerability.
    #
    # ## Features
    #
    # * Checks 301, 302, 303, 307, and 308 HTTP redirects.
    # * Checks `meta` refresh redirects.
    # * Includes random alpha-numeric data in the test values.
    #
    class OpenRedirect < Web

      # The desired redirect URL to use in the test.
      #
      # @return [String]
      attr_reader :test_url

      #
      # Initializes the Open Redirect vulnerability.
      #
      # @param [String] test_url
      #   The desired redirect URL to test the URL with.
      #
      def initialize(url, test_url: self.class.random_test_url, **kwargs)
        super(url,**kwargs)

        @test_url = test_url
      end

      #
      # Generates a random redirect URL to use in tests.
      #
      # @return [String]
      #   A random URL to https://ronin-rb.dev/vulns/open_redirect.html.
      #
      # @api private
      #
      def self.random_test_url
        "https://ronin-rb.dev/vulns/open_redirect.html?id=#{Chars::ALPHA_NUMERIC.random_string(5)}"
      end

      #
      # Tests whther the URL has a vulnerable Open Redirect.
      #
      # @return [Boolean]
      #
      def vulnerable?
        response = exploit(@test_url)

        case response.code
        when '301', '302', '303', '307', '308'
          if (locations = response.get_fields('Location'))
            escaped_test_url = Regexp.escape(@test_url)
            regexp = %r{\A#{escaped_test_url}(?:[\?&].+)?\z}

            locations.last =~ regexp
          end
        else
          content_type = response.content_type

          if content_type && content_type.include?('text/html')
            escaped_test_url = Regexp.escape(CGI.escapeHTML(@test_url))
            regexp = %r{<meta\s+http-equiv=(?:"refresh"|'refresh'|refresh)\s+content=(?:"\d+;\s*url='#{escaped_test_url}'"|'\d+;\s*url="#{escaped_test_url}"'|\d+;url=(?:"#{escaped_test_url}"|'#{escaped_test_url}'))\s*/>}i

            response.body =~ regexp
          end
        end
      end

    end
  end
end
