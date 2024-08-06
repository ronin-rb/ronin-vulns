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

require_relative '../web_vuln'

module Ronin
  module Vulns
    class ReflectedXSS < WebVuln
      #
      # Represents information about the context which the XSS occurs within.
      #
      class Context

        # Where in the HTML the XSS occurs.
        #
        # @return [:double_quoted_attr_value, :single_quoted_attr_value, :unquoted_attr_value, :attr_name, :attr_list, :tag_name, :tag_body, :comment]
        #   The context which the XSS occurs in.
        #   * `:tag_body` occurred within a tag's body (ex: `<tag>XSS...</tag>`)
        #   * `:double_quoted_attr_value` - occurred in a double quoted
        #     attribute value (ex: `<tag name="XSS">...</tag>`)
        #   * `:single_quoted_attr_value` - occurred in a single quoted
        #     attribute value (ex: `<tag name='XSS'>...</tag>`)
        #   * `:unquoted_attr_value` - occurred in an unquoted attribute value
        #     (ex: `<tag name=XSS>...</tag>`)
        #   * `:attr_name` - occurred in an attribute name
        #     (ex: `<tag nameXSS ...>`)
        #   * `:attr_list` - occurred in the attribute list
        #     (ex: `<tag XSS>...</tag>`)
        #   * `:tag_name` - occurred in the tag name (ex: `<tagXSS>...</tag>`)
        #   * `:comment` - occurred in a comment (ex: `<!-- XSS -->`)
        #
        # @api public
        attr_reader :location

        # The name of the parent tag which the XSS occurs in.
        #
        # @return [String, nil]
        #
        # @api public
        attr_reader :tag

        # The attribute name that the XSS occurs in.
        #
        # @return [String, nil]
        #
        # @api public
        attr_reader :attr

        #
        # Initializes the context.
        #
        # @param [:double_quoted_attr_value, :single_quoted_attr_value, :unquoted_attr_value, :attr_name, :attr_list, :tag_name, :tag_body, :comment] location
        #
        # @param [String, nil] tag
        #
        # @param [String, nil] attr
        #
        # @api private
        #
        def initialize(location, tag: nil, attr: nil)
          @location = location

          @tag  = tag
          @attr = attr
        end

        # HTML identifier regexp
        #
        # @api private
        IDENTIFIER = /[A-Za-z0-9_-]+/

        # HTML attribute name regexp.
        #
        # @api private
        ATTR_NAME = IDENTIFIER

        # HTML attribute regexp.
        #
        # @api private
        ATTR = /#{ATTR_NAME}(?:\s*=\s*"[^"]+"|\s*=\s*'[^']+'|=[^"'\s]+)?/

        # HTML attribute list regexp.
        #
        # @api private
        ATTR_LIST = /(?:\s+#{ATTR})*/

        # HTML comment regexp.
        #
        # @api private
        COMMENT = /<![^>]*>/

        # HTML tag name regexp.
        #
        # @api private
        TAG_NAME = IDENTIFIER

        # Regexp matching when an XSS occurs within a tag's inner HTML.
        #
        # @api private
        IN_TAG_BODY = %r{<(#{TAG_NAME})#{ATTR_LIST}\s*(?:>|/>)([^<>]|#{COMMENT})*\z}

        # Regexp matching when an XSS occurs within a double-quoted attribute
        # value.
        #
        # @api private
        IN_DOUBLE_QUOTED_ATTR_VALUE = /<(#{TAG_NAME})#{ATTR_LIST}\s+(#{ATTR_NAME})\s*=\s*"[^"]+\z/

        # Regexp matching when an XSS occurs within a single-quoted attribute
        # value.
        #
        # @api private
        IN_SINGLE_QUOTED_ATTR_VALUE = /<(#{TAG_NAME})#{ATTR_LIST}\s+(#{ATTR_NAME})\s*=\s*'[^']+\z/

        # Regexp matching when an XSS occurs within an unquoted attribute value.
        #
        # @api private
        IN_UNQUOTED_ATTR_VALUE = /<(#{TAG_NAME})#{ATTR_LIST}\s+(#{ATTR_NAME})=[^"'\s]+\z/

        # Regexp matching when an XSS occurs within an attribute's name.
        #
        # @api private
        IN_ATTR_NAME = /<(#{TAG_NAME})#{ATTR_LIST}\s+(#{ATTR_NAME})\z/

        # Regexp matching when an XSS occurs within a tag's attribute list.
        #
        # @api private
        IN_ATTR_LIST = /<(#{TAG_NAME})#{ATTR_LIST}\s+\z/

        # Regexp matching when an XSS occurs within a tag's name.
        #
        # @api private
        IN_TAG_NAME = /<(#{TAG_NAME})\z/

        # Regexp matching when an XSS occurs within a comment.
        #
        # @api private
        IN_COMMENT = /<![^>]*\z/

        #
        # Determine the context of the XSS by checking the characters that come
        # before the given index.
        #
        # @param [String] body
        #   The HTML response body to inspect.
        #
        # @param [Integer] index
        #   The index which the XSS occurs at.
        #
        # @return [Context]
        #   The context which the XSS occurs in.
        #
        # @api private
        #
        def self.identify(body,index)
          prefix = body[0,index]

          if    (match = prefix.match(IN_TAG_BODY))
            new(:tag_body, tag: match[1])
          elsif (match = prefix.match(IN_DOUBLE_QUOTED_ATTR_VALUE))
            new(:double_quoted_attr_value, tag: match[1], attr: match[2])
          elsif (match = prefix.match(IN_SINGLE_QUOTED_ATTR_VALUE))
            new(:single_quoted_attr_value, tag: match[1], attr: match[2])
          elsif (match = prefix.match(IN_UNQUOTED_ATTR_VALUE))
            new(:unquoted_attr_value, tag: match[1], attr: match[2])
          elsif (match = prefix.match(IN_ATTR_NAME))
            new(:attr_name, tag: match[1], attr: match[2])
          elsif (match = prefix.match(IN_ATTR_LIST))
            new(:attr_list, tag: match[1])
          elsif (match = prefix.match(IN_TAG_NAME))
            new(:tag_name, tag: match[1])
          elsif prefix.match?(IN_COMMENT)
            new(:comment)
          end
        end

        # The minimum set of required characters needed for an XSS.
        #
        # @api private
        MINIMAL_REQUIRED_CHARS = Set['>', ' ', '/', '<']

        # The mapping of contexts and their required characters.
        #
        # @api private
        REQUIRED_CHARS = {
          double_quoted_attr_value: MINIMAL_REQUIRED_CHARS + ['"'],
          single_quoted_attr_value: MINIMAL_REQUIRED_CHARS + ["'"],
          unquoted_attr_value:      MINIMAL_REQUIRED_CHARS,

          attr_name: MINIMAL_REQUIRED_CHARS,
          attr_list: MINIMAL_REQUIRED_CHARS,
          tag_name:  MINIMAL_REQUIRED_CHARS,
          tag_body:  MINIMAL_REQUIRED_CHARS,
          comment:   MINIMAL_REQUIRED_CHARS
        }

        #
        # Determines if the XSS is viable, given the context and the allowed
        # characters.
        #
        # @param [Set<String>] allowed_chars
        #   The allowed characters.
        #
        # @return [Boolean]
        #   Specifies whether enough characters are allowed to perform an XSS in
        #   the given context.
        #
        # @api private
        #
        def viable?(allowed_chars)
          required_chars = REQUIRED_CHARS.fetch(@location) do
            raise(NotImplementedError,"cannot determine viability for unknown XSS location type: #{@location.inspect}")
          end

          allowed_chars.superset?(required_chars)
        end

      end
    end
  end
end
