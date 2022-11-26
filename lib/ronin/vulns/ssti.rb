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
require 'ronin/vulns/ssti/test_expression'

module Ronin
  module Vulns
    #
    # Represents a Server Side Template Injection (SSTI) vulnerability.
    #
    class SSTI < WebVuln

      # List of common Server Side Template Injection (SSTI) escapes.
      #
      # @api private
      ESCAPES = [
        nil, # does not escape the expression
        ->(expression) { "{{#{expression}}}"    },
        ->(expression) { "${#{expression}}"     },
        ->(expression) { "${{#{expression}}}"   },
        ->(expression) { "\#{#{expression}}"    },
        ->(expression) { "<%= #{expression} %>" }
      ]

      # How to escape the payload so that it's executed.
      #
      # @return [Proc, nil]
      #   The proc that will accept a String and return a String, or `nil` to
      #   indicate that the payload will not be escaped.
      attr_reader :escape

      # The test expression to use when testing the URL for SSTI.
      #
      # @return [TestExpression]
      attr_reader :test_expr

      #
      # Initializes the Server Side Template Injection (SSTI) vulnerability.
      #
      # @param [String, URI::HTTP] url
      #   The URL to exploit.
      #
      # @param [Proc, nil] escape
      #   How to escape a given payload. Either a proc that will accept a String
      #   and return a String, or `nil` to indicate that the payload will not
      #   be escaped.
      #
      # @param [TestExpression] test_expr
      #   The test payload and expected result to check for when testing the URL
      #   for SSTI.
      #
      def initialize(url, escape: nil,
                          test_expr: self.class.random_test,
                          **kwargs)
        super(url,**kwargs)

        @escape    = escape
        @test_expr = test_expr

        unless @test_expr
          raise(ArgumentError,"must specify both a test expression")
        end
      end

      #
      # Generates a random `N*M` SSTI test.
      #
      # @return [TestExpression]
      #   A random test expression.
      #
      def self.random_test
        int1 = rand(999) + 1_000
        int2 = rand(999) + 1_000

        string  = "#{int1}*#{int2}"
        result  = (int1 * int2).to_s

        return TestExpression.new(string,result)
      end

      #
      # Scans the URL for Server Side Template Injection (SSTI) vulnerabilities.
      #
      # @param [URI::HTTP, String] url
      #   The URL to scan.
      #
      # @param [Hash{Symbol => Object}] kwargs
      #   Additional keyword arguments for {#initialize}.
      #
      # @option kwargs [Proc, nil] :escape
      #   The escape method to use. If `escape:` is not given, then all escapes
      #   in {ESCAPES} will be tested..
      #   
      # @option kwargs [Array<Symbol, String>, Symbol, String, true, nil] :query_params
      #   The query param name(s) to test.
      #
      # @option kwargs [Array<Symbol, String>, Symbol, String, nil] :header_names
      #   The header name(s) to test.
      #
      # @option kwargs [Array<Symbol, String>, Symbol, String, true, nil] :cookie_params
      #   The cookie param name(s) to test.
      #
      # @option kwargs [Array<Symbol, String>, Symbol, String, nil] :form_params
      #   The form param name(s) to test.
      #
      # @option kwargs [Ronin::Support::Network::HTTP, nil] :http
      #   An HTTP session to use for testing the LFI.
      #
      # @option kwargs [Hash{String => String}, nil] :headers
      #   Additional headers to send with requests.
      #
      # @option kwargs [String, Ronin::Support::Network::HTTP::Cookie, nil] :cookie
      #   Additional cookie params to send with requests.
      #
      # @option kwargs [String, nil] :referer
      #   Optional `Referer` header to send with requests.
      #
      # @option kwargs [Hash{String => String}, nil] :form_data
      #   Additional form data to send with requests.
      #
      # @yield [vuln]
      #   If a block is given it will be yielded each discovered vulnerability.
      #
      # @yieldparam [SSTI] vuln
      #   A discovered SSTI vulnerability in the URL.
      #
      # @return [Array<SSTI>]
      #   All discovered SSTI vulnerabilities.
      #
      def self.scan(url, **kwargs,&block)
        if kwargs.has_key?(:escape)
          super(url, **kwargs, &block)
        else
          ESCAPES.each do |escape|
            super(url, escape: escape, **kwargs, &block)
          end
        end
      end

      #
      # Escapes the payload using {#escape}.
      #
      # @param [String] payload
      #
      # @return [String]
      #
      def encode_payload(payload)
        if @escape then @escape.call(payload)
        else            payload
        end
      end

      #
      # Exploits the Server Side Template Injection (SSTI) vulnerability by
      # performing an HTTP request with the given template expression.
      #
      # @param [String] payload
      #   The template expression to attempt to execute.
      #
      # @return [Net::HTTPResponse]
      #   The HTTP response for the SSTI request.
      #
      def exploit(payload,**kwargs)
        super(encode_payload(payload),**kwargs)
      end

      #
      # Determine whether the URL is vulnerable to Server Side Template
      # Injection (SSTI).
      #
      # @return [Boolean]
      #
      def vulnerable?
        response = exploit(@test_expr.string)
        body     = response.body

        return body.include?(@test_expr.result)
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
        :ssti
      end

    end
  end
end
