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

require_relative '../vuln'

require 'ronin/support/network/http/cookie'
require 'ronin/support/network/http/user_agents'

require 'uri/query_params'

module Ronin
  module Vulns
    class WebVuln < Vuln
      #
      # Represents a HTTP request.
      #
      # @api private
      #
      class HTTPRequest

        # The URL of the request.
        #
        # @return [URI::HTTP]
        attr_reader :url

        # The HTTP request method.
        #
        # @return [:copy, :delete, :get, :head, :lock, :mkcol, :move,
        #         :options, :patch, :post, :propfind, :proppatch, :put,
        #         :trace, :unlock]
        attr_reader :request_method

        # The user to authenticate as.
        #
        # @return [String, nil]
        attr_reader :user

        # The password to authenticate with.
        #
        # @return [String, nil]
        attr_reader :password

        # The optional HTTP `User-Agent` header to send with each request.
        #
        # @return [String, :random, :chrome, :chrome_linux, :chrome_macos,
        #          :chrome_windows, :chrome_iphone, :chrome_ipad,
        #          :chrome_android, :firefox, :firefox_linux, :firefox_macos,
        #          :firefox_windows, :firefox_iphone, :firefox_ipad,
        #          :firefox_android, :safari, :safari_macos, :safari_iphone,
        #          :safari_ipad, :edge, :linux, :macos, :windows, :iphone,
        #          :ipad, :android, nil]
        #
        # @since 0.2.0
        attr_reader :user_agent

        # The optional HTTP `Referer` header for the request.
        #
        # @return [String, nil]
        attr_reader :referer

        # The query param for the request.
        #
        # @return [Hash{String,Symbol => String}, nil]
        attr_reader :query_params

        # Additional `Cookie` header for the request.
        #
        # @return [Ronin::Support::Network::HTTP::Cookie, nil]
        attr_reader :cookie

        # Additional HTTP header names and values to add to the request.
        #
        # @return [Hash{Symbol,String => String}, nil]
        attr_reader :headers

        # The form data that may be sent in the body of the request.
        #
        # @return [Hash{String => Object}, nil]
        attr_reader :form_data

        #
        # Initializes the HTTP request object.
        #
        # @param [URI::HTTP] url
        #   The URL to test or exploit.
        #
        # @param [:copy, :delete, :get, :head, :lock, :mkcol, :move,
        #         :options, :patch, :post, :propfind, :proppatch, :put,
        #         :trace, :unlock] request_method
        #   The HTTP request mehtod for each request.
        #
        # @param [String, nil] user
        #   The user to authenticate as.
        #
        # @param [String, nil] password
        #   The password to authenticate with.
        #
        # @param [Hash{Symbol,String => String}, nil] query_params
        #   Additional URL query params for the request.
        #
        # @param [Hash{Symbol,String => String}, nil] headers
        #   Additional HTTP header names and values to add to the request.
        #
        # @param [String, :random, :chrome, :chrome_linux, :chrome_macos, :chrome_windows, :chrome_iphone, :chrome_ipad, :chrome_android, :firefox, :firefox_linux, :firefox_macos, :firefox_windows, :firefox_iphone, :firefox_ipad, :firefox_android, :safari, :safari_macos, :safari_iphone, :safari_ipad, :edge, :linux, :macos, :windows, :iphone, :ipad, :android, nil] user_agent
        #   Optional `User-Agent` header to send with requests.
        #
        # @param [String, Hash{String => String}, nil] cookie
        #   Additional `Cookie` header for the request..
        #
        # @param [Hash, nil] form_data
        #   The form data that may be sent in the body of the request.
        #
        def initialize(url, request_method: :get,
                            user:           nil,
                            password:       nil,
                            user_agent:     nil,
                            referer:        nil,
                            query_params:   nil,
                            headers:        nil,
                            cookie:         nil,
                            form_data:      nil)
          @url = url

          if query_params && !query_params.empty?
            @url = url.dup

            @url.query_params = query_params
          end

          @request_method = request_method
          @user           = user
          @password       = password
          @user_agent     = user_agent
          @referer        = referer

          @query_params = query_params
          @cookie       = if cookie
                            Support::Network::HTTP::Cookie.new(cookie)
                          end
          @headers      = headers
          @form_data    = form_data
        end

        #
        # The `User-Agent` string for the request.
        #
        # @return [String, nil]
        #
        # @since 0.2.0
        #
        def user_agent_string
          case @user_agent
          when String, nil then @user_agent
          else
            Support::Network::HTTP::UserAgents[@user_agent]
          end
        end

        #
        # Converts the HTTP request to a `curl` command.
        #
        # @return [String]
        #
        def to_curl
          escape = ->(str) { "'#{str.to_s.tr("'","\\'")}'" }

          command = ['curl']

          if @request_method != :get
            command << '--request' << @request_method.upcase
          end

          if (@user || @password)
            command << '--user' << escape.call("#{@user}:#{@password}")
          end

          if @user_agent
            command << '--user-agent' << escape.call(user_agent_string)
          end

          if @referer
            command << '--referer' << escape.call(@referer)
          end

          if (@cookie && !@cookie.empty?)
            command << '--cookie' << escape.call(@cookie)
          end

          if @headers
            @headers.each do |name,value|
              command << '--header' << escape.call("#{name}: #{value}")
            end
          end

          if (@form_data && !@form_data.empty?)
            form_string = URI.encode_www_form(@form_data)
            command << '--form-string' << escape.call(form_string)
          end

          command << escape.call(@url)

          return command.join(' ')
        end

        # HTTP newline deliminator.
        CRLF = "\r\n"

        #
        # Converts the HTTP request to a raw HTTP request.
        #
        # @return [String]
        #
        def to_http
          request = []
          request << "#{@request_method.upcase} #{@url.request_uri} HTTP/1.1"

          if (@form_data && !@form_data.empty?)
            request << "Content-Type: x-www-form-urlencoded"
          end

          if (@user || @password)
            basic_auth = ["#{@user}:#{@password}"].pack('m0')
            request << "Authorization: Basic #{basic_auth}"
          end

          request << "User-Agent: #{user_agent_string}" if @user_agent
          request << "Referer: #{@referer}" if @referer
          request << "Cookie: #{@cookie}"   if (@cookie && !@cookie.empty?)

          if @headers
            @headers.each do |name,value|
              request << "#{name}: #{value}"
            end
          end

          if (@form_data && !@form_data.empty?)
            request << ''
            request << URI.encode_www_form(@form_data)
          end

          return request.join(CRLF) << CRLF
        end
      end
    end
  end
end
