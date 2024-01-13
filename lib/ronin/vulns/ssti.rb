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
      ESCAPES = {
        nil => nil, # does not escape the expression

        double_curly_braces:        ->(expression) { "{{#{expression}}}"    },
        dollar_curly_braces:        ->(expression) { "${#{expression}}"     },
        dollar_double_curly_braces: ->(expression) { "${{#{expression}}}"   },
        pound_curly_braces:         ->(expression) { "\#{#{expression}}"    },
        angle_brackets_percent:     ->(expression) { "<%= #{expression} %>" }
      }

      # The type of SSTI escape used.
      #
      # @return [:double_curly_braces, :dollar_curly_braces, :dollar_double_curly_braces, :pound_curly_braces, :angle_brackets_percent, :custom, nil]
      #
      # @since 0.2.0
      attr_reader :escape_type

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
      # @param [:double_curly_braces, :dollar_curly_braces, :dollar_double_curly_braces, :pound_curly_braces, :angle_brackets_percent, :custom, Proc, nil] escape
      #   How to escape a given payload. Either a proc that will accept a String
      #   and return a String, a Symbol describing the template syntax to use,
      #   or `nil` to indicate that the payload will not be escaped.
      #
      # @param [TestExpression] test_expr
      #   The test payload and expected result to check for when testing the URL
      #   for SSTI.
      #
      # @raise [ArgumentError]
      #   An unknown `escape_type:` or `escape:` value was given, or no
      #   `test_expr:` was given.
      #
      def initialize(url, escape:    nil,
                          test_expr: self.class.random_test,
                          **kwargs)
        super(url,**kwargs)

        case escape
        when Symbol
          @escape_type = escape
          @escape      = ESCAPES.fetch(escape) do
                           raise(ArgumentError,"unknown template syntax: #{escape_type.inspect}")
                         end
        when Proc
          @escape_type = :custom
          @escape      = escape
        when nil # no-op
        else
          raise(ArgumentError,"invalid escape type, must be a Symbol, Proc, or nil: #{escape.inspect}")
        end

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
        int1 = rand(1_000..1_999)
        int2 = rand(1_000..1_999)

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
      # @param [Array<Symbol, Proc>, Symbol, Proc, nil] escape
      #   The escape method to use. If `escape:` is not given, then all escapes
      #   names in {ESCAPES} will be tested..
      #
      # @param [Hash{Symbol => Object}] kwargs
      #   Additional keyword arguments for {#initialize}.
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
      def self.scan(url, escape: ESCAPES.keys, **kwargs,&block)
        vulns = []

        Array(escape).each do |escape_value|
          vulns.concat(super(url, escape: escape_value, **kwargs, &block))
        end

        return vulns
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
