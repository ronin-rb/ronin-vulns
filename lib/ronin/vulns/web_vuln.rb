# frozen_string_literal: true
#
# ronin-vulns - A Ruby library for blind vulnerability testing.
#
# Copyright (c) 2022-2026 Hal Brodigan (postmodern.mod3 at gmail.com)
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

require_relative 'vuln'
require_relative 'web_vuln/http_request'

require 'ronin/support/network/http'
require 'chars'

module Ronin
  module Vulns
    #
    # The base class for all web vulnerabilities.
    #
    class WebVuln < Vuln

      # The URL to test or exploit.
      #
      # @return [URI::HTTP]
      attr_reader :url

      # The query param to test or exploit.
      #
      # @return [String, Symbol, nil]
      attr_reader :query_param

      # The HTTP Header name to test or exploit.
      #
      # @return [String, Symbol, nil]
      attr_reader :header_name

      # The `Cookie:` param name to test or exploit.
      #
      # @return [String, Symbol, nil]
      attr_reader :cookie_param

      # The form param name to test or exploit.
      #
      # @return [String, Symbol, nil]
      attr_reader :form_param

      # An HTTP session to use for testing the URL.
      #
      # @return [Ronin::Support::Network::HTTP, nil]
      attr_reader :http

      # The HTTP request method for each request.
      #
      # @return [:copy, :delete, :get, :head, :lock, :mkcol, :move,
      #         :options, :patch, :post, :propfind, :proppatch, :put,
      #         :trace, :unlock]
      attr_reader :request_method

      # The query params to send with each request.
      #
      # @return [Hash{String,Symbol => String}]
      attr_reader :query_params

      # The user to authenticate as.
      #
      # @return [String, nil]
      attr_reader :user

      # The password to authenticate with.
      #
      # @return [String, nil]
      attr_reader :password

      # Additional HTTP header names and values to add to the request.
      #
      # @return [Hash{Symbol,String => String}, nil]
      attr_reader :headers

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

      # Additional `Cookie` header. If a `Hash` is given, it will be converted
      # to a `String` using `Ronin::Support::Network::HTTP::Cookie`.
      #
      # @return [Hash{String => String}, nil]
      attr_reader :cookie

      # The form data that may be sent in the body of the request.
      #
      # @return [Hash, nil]
      attr_reader :form_data

      # The optional HTTP `Referer` header to send with each request.
      #
      # @return [String, nil]
      attr_reader :referer

      #
      # Initializes the web vulnerability.
      #
      # @param [URI::HTTP, String] url
      #   The URL to test or exploit.
      #
      # @param [String, Symbol, nil] query_param
      #   The query param to test or exploit.
      #
      # @param [String, Symbol, nil] header_name
      #   The HTTP Header name to test or exploit.
      #
      # @param [String, Symbol, nil] cookie_param
      #   The `Cookie:` param name to test or exploit.
      #
      # @param [String, Symbol, nil] form_param
      #   The form param name to test or exploit.
      #
      # @param [Ronin::Support::Network::HTTP, nil] http
      #   An HTTP session to use for testing the URL.
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
      # @param [Hash{Symbol,String => String}, nil] headers
      #   Additional HTTP header names and values to add to the request.
      #
      # @param [String, :random, :chrome, :chrome_linux, :chrome_macos,
      #          :chrome_windows, :chrome_iphone, :chrome_ipad,
      #          :chrome_android, :firefox, :firefox_linux, :firefox_macos,
      #          :firefox_windows, :firefox_iphone, :firefox_ipad,
      #          :firefox_android, :safari, :safari_macos, :safari_iphone,
      #          :safari_ipad, :edge, :linux, :macos, :windows, :iphone,
      #          :ipad, :android, nil] user_agent
      #   The optional HTTP `User-Agent` header to send with each request.
      #
      # @param [Hash{String => String}, nil] cookie
      #   Additional `Cookie` header. If a `Hash` is given, it will be
      #   converted to a `String` using `Ronin::Support::Network::HTTP::Cookie`.
      #
      # @param [Hash, nil] form_data
      #   The form data that may be sent in the body of the request.
      #
      # @param [String, nil] referer
      #   The optional HTTP `Referer` header to send with each request.
      #
      def initialize(url, query_param:    nil,
                          header_name:    nil,
                          cookie_param:   nil,
                          form_param:     nil,
                          # http keyword arguments
                          http:           nil,
                          request_method: :get,
                          user:           nil,
                          password:       nil,
                          headers:        nil,
                          user_agent:     nil,
                          cookie:         nil,
                          form_data:      nil,
                          referer:        nil)
        @url = URI(url)

        @query_param  = String(query_param)  if query_param
        @header_name  = String(header_name)  if header_name
        @cookie_param = String(cookie_param) if cookie_param
        @form_param   = String(form_param)   if form_param

        @http = http || Support::Network::HTTP.connect_uri(@url)

        @request_method = request_method
        @query_params   = @url.query_params
        @user           = user
        @password       = password
        @headers        = headers
        @user_agent     = user_agent
        @cookie         = cookie
        @form_data      = form_data
        @referer        = referer
      end

      #
      # Internal method that tests combinations of configurations for a specific
      # query param, header name, cookie param, or form param.
      #
      # @param [URI::HTTP] url
      #   The URL to test.
      #
      # @param [Ronin::Support::Network::HTTP, nil] http
      #   An HTTP session to use for testing the URL.
      #
      # @param [Hash{Symbol => Object}] kwargs
      #   Additional keyword arguments for {#initialize}.
      #
      # @option kwargs [Symbol, String, nil] :query_param
      #   The query param name to test.
      #
      # @option kwargs [Symbol, String, nil] :header_name
      #   The header name to test.
      #
      # @option kwargs [Symbol, String, true, nil] :cookie_param
      #   The cookie param name to test.
      #
      # @option kwargs [Symbol, String, nil] :form_param
      #   The form param name to test.
      #
      # @return [WebVuln, nil]
      #   The first discovered web vulnerability for the specific query param,
      #   header name, cookie param, or form param.
      #
      # @api private
      #
      # @since 0.2.0
      #
      def self.test_param(url, http: , **kwargs)
        vuln = new(url, http: http, **kwargs)

        return vuln if vuln.vulnerable?
      end

      #
      # Scans the query parameters of the URL.
      #
      # @param [URI::HTTP, String] url
      #   The URL to scan.
      #
      # @param [Array<Symbol, String>, nil] query_params
      #   The query param name(s) to test. If no query param(s) are given,
      #   then all query params in the URL will be scanned.
      #
      # @param [Ronin::Support::Network::HTTP, nil] http
      #   An HTTP session to use when testing for web vulnerabilities.
      #
      # @yield [vuln]
      #   If a block is given it will be yielded each discovered web
      #   vulnerability.
      #
      # @yieldparam [Web] vuln
      #   A discovered web vulnerability in the URL's query params.
      #
      # @return [Array<Web>]
      #   All discovered web vulnerabilities.
      #
      def self.scan_query_params(url,query_params=nil, http: nil, **kwargs)
        url    = URI(url)
        http ||= Support::Network::HTTP.connect_uri(url)

        query_params ||= url.query_params.keys
        vulns          = []

        query_params.each do |param|
          if (vuln = test_param(url, query_param: param, http: http, **kwargs))
            yield vuln if block_given?
            vulns << vuln
          end
        end

        return vulns
      end

      #
      # Scans the URL and request headers.
      #
      # @param [URI::HTTP, String] url
      #   The URL to scan.
      #
      # @param [Array<String, Symbol>] header_names
      #   The header name(s) to test.
      #
      # @param [Ronin::Support::Network::HTTP, nil] http
      #   An HTTP session to use when testing for web vulnerabilities.
      #
      # @yield [vuln]
      #   If a block is given it will be yielded each discovered web
      #   vulnerability.
      #
      # @yieldparam [Web] vuln
      #   A discovered web vulnerability in the URL and one of the header names.
      #
      # @return [Array<Web>]
      #   All discovered web vulnerabilities.
      #
      def self.scan_headers(url,header_names, http: nil, **kwargs)
        url    = URI(url)
        http ||= Support::Network::HTTP.connect_uri(url)

        vulns = []

        header_names.each do |header_name|
          if (vuln = test_param(url, header_name: header_name, http: http, **kwargs))
            yield vuln if block_given?
            vulns << vuln
          end
        end

        return vulns
      end

      #
      # Scans the URL and the `Cookie` header params.
      #
      # @param [URI::HTTP, String] url
      #   The URL to scan.
      #
      # @param [Array<Symbol, String>, nil] cookie_params
      #   The cookie param name(s) to test. If not given, then the URL will be
      #   requested and the `Set-Cookie` params from the response will be
      #   tested instead.
      #
      # @param [Ronin::Support::Network::HTTP, nil] http
      #   An HTTP session to use when testing for web vulnerabilities.
      #
      # @yield [vuln]
      #   If a block is given it will be yielded each discovered web
      #   vulnerability.
      #
      # @yieldparam [Web] vuln
      #   A discovered web vulnerability in the URL and one of the `Cookie`
      #   header params.
      #
      # @return [Array<Web>]
      #   All discovered web vulnerabilities.
      #
      def self.scan_cookie_params(url,cookie_params=nil, http: nil, **kwargs)
        url    = URI(url)
        http ||= Support::Network::HTTP.connect_uri(url)

        unless cookie_params
          cookie_params = Set.new

          http.get_cookies(url.request_uri).each do |set_cookie|
            cookie_params.merge(set_cookie.params.keys)
          end
        end

        vulns = []

        cookie_params.each do |cookie_param|
          if (vuln = test_param(url, cookie_param: cookie_param, http: http, **kwargs))
            yield vuln if block_given?
            vulns << vuln
          end
        end

        return vulns
      end

      #
      # Scans the URL and the form params.
      #
      # @param [URI::HTTP, String] url
      #   The URL to scan.
      #
      # @param [Array<Symbol, String>, nil] form_params
      #   The form param name(s) to test.
      #
      # @param [Ronin::Support::Network::HTTP, nil] http
      #   An HTTP session to use when testing for web vulnerabilities.
      #
      # @yield [vuln]
      #   If a block is given it will be yielded each discovered web
      #   vulnerability.
      #
      # @yieldparam [Web] vuln
      #   A discovered web vulnerability in the URL and one of the form params.
      #
      # @return [Array<Web>]
      #   All discovered web vulnerabilities.
      #
      def self.scan_form_params(url,form_params=nil, http: nil, form_data: {}, **kwargs)
        url    = URI(url)
        http ||= Support::Network::HTTP.connect_uri(url)

        form_params ||= form_data.keys
        vulns         = []

        form_params.each do |form_param|
          if (vuln = test_param(url, form_param: form_param, form_data: form_data, http: http, **kwargs))
            yield vuln if block_given?
            vulns << vuln
          end
        end

        return vulns
      end

      #
      # Scans the URL for web vulnerabilities.
      #
      # @param [URI::HTTP, String] url
      #   The URL to scan.
      #
      # @param [Array<Symbol, String>, true, nil] query_params
      #   The query param name(s) to test.
      #
      # @param [Array<Symbol, String>, nil] header_names
      #   The header name(s) to test.
      #
      # @param [Array<Symbol, String>, true, nil] cookie_params
      #   The cookie param name(s) to test.
      #
      # @param [Array<Symbol, String>, nil] form_params
      #   The form param name(s) to test.
      #
      # @param [Ronin::Support::Network::HTTP, nil] http
      #   An HTTP session to use for testing the LFI.
      #
      # @param [Hash{Symbol => Object}] kwargs
      #   Additional keyword arguments for {#initialize}.
      #
      # @option kwargs [:copy, :delete, :get, :head, :lock, :mkcol, :move,
      #                 :options, :patch, :post, :propfind, :proppatch, :put,
      #                 :trace, :unlock] :request_method
      #   The HTTP request mehtod for each request.
      #
      # @option kwargs [String, nil] :user
      #   The user to authenticate as.
      #
      # @option kwargs [String, nil] :password
      #   The password to authenticate with.
      #
      # @option kwargs [Hash{String => String}, nil] :headers
      #   Additional headers to send with requests.
      #
      # @option kwargs [String, :random, :chrome, :chrome_linux, :chrome_macos, :chrome_windows, :chrome_iphone, :chrome_ipad, :chrome_android, :firefox, :firefox_linux, :firefox_macos, :firefox_windows, :firefox_iphone, :firefox_ipad, :firefox_android, :safari, :safari_macos, :safari_iphone, :safari_ipad, :edge, :linux, :macos, :windows, :iphone, :ipad, :android, nil] :user_agent
      #   Optional `User-Agent` header to send with requests.
      #
      # @option kwargs [Hash{String => String}, Ronin::Support::Network::HTTP::Cookie, nil] :cookie
      #   Additional cookie params to send with requests.
      #
      # @option kwargs [String, nil] :referer
      #   Optional `Referer` header to send with requests.
      #
      # @option kwargs [Hash{String => String}, nil] :form_data
      #   Additional form data to send with requests.
      #
      # @yield [vuln]
      #   If a block is given it will be yielded each discovered web
      #   vulnerability.
      #
      # @yieldparam [WebVuln] vuln
      #   A discovered web vulnerability in the URL.
      #
      # @return [Array<WebVuln>]
      #   All discovered web vulnerabilities.
      #
      def self.scan(url, query_params:  nil,
                         header_names:  nil,
                         cookie_params: nil,
                         form_params:   nil,
                         http:          nil,
                         **kwargs,
                         &block)
        url    = URI(url)
        http ||= Support::Network::HTTP.connect_uri(url)
        vulns  = []

        if (query_params.nil? && header_names.nil? && cookie_params.nil? && form_params.nil?)
          vulns.concat(scan_query_params(url, http: http, **kwargs,&block))
        else
          if query_params
            vulns.concat(
              case query_params
              when true
                scan_query_params(url, http: http, **kwargs,&block)
              else
                scan_query_params(url,query_params, http: http, **kwargs,&block)
              end
            )
          end

          if header_names
            vulns.concat(
              scan_headers(url,header_names, http: http, **kwargs,&block)
            )
          end

          if cookie_params
            vulns.concat(
              case cookie_params
              when true
                scan_cookie_params(url, http: http, **kwargs,&block)
              else
                scan_cookie_params(url,cookie_params, http: http, **kwargs,&block)
              end
            )
          end

          if form_params
            vulns.concat(
              case form_params
              when true
                scan_form_params(url, http: http, **kwargs,&block)
              else
                scan_form_params(url,form_params, http: http, **kwargs,&block)
              end
            )
          end
        end

        return vulns
      end

      #
      # Tests the URL for a web vulnerability and returns the first found
      # vulnerability.
      #
      # @param [URI::HTTP, String] url
      #   The URL to test.
      #
      # @param [Hash{Symbol => Object}] kwargs
      #   Additional keyword arguments for {scan}.
      #
      # @option kwargs [Array<Symbol, String>, true, nil] :query_params
      #   The query param name(s) to test.
      #
      # @option kwargs [Array<Symbol, String>, nil] :header_names
      #   The header name(s) to test.
      #
      # @option kwargs [Array<Symbol, String>, true, nil] :cookie_params
      #   The cookie param name(s) to test.
      #
      # @option kwargs [Array<Symbol, String>, nil] :form_params
      #   The form param name(s) to test.
      #
      # @option kwargs [Ronin::Support::Network::HTTP, nil] :http
      #   An HTTP session to use for testing the LFI.
      #
      # @option kwargs [:copy, :delete, :get, :head, :lock, :mkcol, :move,
      #                 :options, :patch, :post, :propfind, :proppatch, :put,
      #                 :trace, :unlock] :request_method
      #   The HTTP request mehtod for each request.
      #
      # @option kwargs [String, nil] :user
      #   The user to authenticate as.
      #
      # @option kwargs [String, nil] :password
      #   The password to authenticate with.
      #
      # @option kwargs [Hash{String => String}, nil] :headers
      #   Additional headers to send with requests.
      #
      # @option kwargs [String, :random, :chrome, :chrome_linux, :chrome_macos, :chrome_windows, :chrome_iphone, :chrome_ipad, :chrome_android, :firefox, :firefox_linux, :firefox_macos, :firefox_windows, :firefox_iphone, :firefox_ipad, :firefox_android, :safari, :safari_macos, :safari_iphone, :safari_ipad, :edge, :linux, :macos, :windows, :iphone, :ipad, :android, nil] :user_agent
      #   Optional `User-Agent` header to send with requests.
      #
      # @option kwargs [Hash{String => String}, Ronin::Support::Network::HTTP::Cookie, nil] :cookie
      #   Additional cookie params to send with requests.
      #
      # @option kwargs [String, nil] :referer
      #   Optional `Referer` header to send with requests.
      #
      # @option kwargs [Hash{String => String}, nil] :form_data
      #   Additional form data to send with requests.
      #
      # @return [WebVuln, nil]
      #   The first discovered web vulnerability or `nil` if no vulnerabilities
      #   were discovered.
      #
      def self.test(url,**kwargs)
        scan(url,**kwargs) do |vuln|
          return vuln
        end

        return nil
      end

      #
      # Performs a normal request for the URL to test.
      #
      # @param [Hash{Symbol => Object}] kwargs
      #   Additional keyword arguments for
      #   `Ronin::Support::Network::HTTP#request`.
      #
      # @return [Net::HTTPResponse]
      #
      def request(**kwargs)
        @http.request(
          @request_method, @url.path, user:         @user,
                                      password:     @password,
                                      query_params: @query_params,
                                      user_agent:   @user_agent,
                                      cookie:       @cookie,
                                      referer:      @referer,
                                      headers:      @headers,
                                      form_data:    @form_data,
                                      **kwargs
        )
      end

      #
      # The exploit query params with the payload injected.
      #
      # @param [#to_s] payload
      #   The payload to use for the exploit.
      #
      # @return [Hash{String,Symbol => String}]
      #   The {#query_params} with the payload injected. If {#query_param} is
      #   not set, then the unmodified {#query_params} will be returned.
      #
      def exploit_query_params(payload)
        if @query_param
          if @query_params
            @query_params.merge(@query_param.to_s => payload)
          else
            {@query_param.to_s => payload}
          end
        else
          @query_params
        end
      end

      #
      # The exploit headers with the payload injected.
      #
      # @param [#to_s] payload
      #   The payload to use for the exploit.
      #
      # @return [Hash{String,Symbol => String}, nil]
      #   The {#headers} with the payload injected. If {#header_name} is not
      #   set, then the unmodified {#headers} will be returned.
      #
      def exploit_headers(payload)
        if @header_name
          if @headers
            @headers.merge(@header_name.to_s => payload)
          else
            {@header_name.to_s => payload}
          end
        else
          @headers
        end
      end

      #
      # The exploit cookie params with the payload injected.
      #
      # @param [#to_s] payload
      #   The payload to use for the exploit.
      #
      # @return [Hash{String,Symbol => String}, Ronin::Support::Network::HTTP::Cookie, nil]
      #   The {#cookie} with the payload injected. If {#cookie_param} is not
      #   set, then the unmodified {#cookie} will be returned.
      #
      def exploit_cookie(payload)
        if @cookie_param
          if @cookie
            @cookie.merge(@cookie_param.to_s => payload)
          else
            {@cookie_param.to_s => payload}
          end
        else
          @cookie
        end
      end

      #
      # The exploit form data with the payload injected.
      #
      # @param [#to_s] payload
      #   The payload to use for the exploit.
      #
      # @return [Hash{String,Symbol => String}, nil]
      #   The {#form_data} with the payload injected. If {#form_param} is not
      #   set, then the unmodified {#form_data} will be returned.
      #
      def exploit_form_data(payload)
        if @form_param
          if @form_data
            @form_data.merge(@form_param.to_s => payload)
          else
            {@form_param.to_s => payload}
          end
        else
          @form_data
        end
      end

      #
      # Place holder method for applying additional encoding to the payload.
      #
      # @param [#to_s] payload
      #   The payload to encode.
      #
      # @return [String]
      #   The encoded payload.
      #
      def encode_payload(payload)
        payload.to_s
      end

      #
      # Exploits the web vulnerability by sending an HTTP request.
      #
      # @param [String] payload
      #   The payload for the web vulnerability.
      #
      # @param [Hash{Symbol => Object}] kwargs
      #   Additional keyword arguments for
      #   `Ronin::Support::Network::HTTP#request`.
      #
      # @return [Net::HTTPResponse]
      #
      def exploit(payload,**kwargs)
        payload = encode_payload(payload)

        request(
          query_params: exploit_query_params(payload),
          cookie:       exploit_cookie(payload),
          headers:      exploit_headers(payload),
          form_data:    exploit_form_data(payload),
          **kwargs
        )
      end

      #
      # The original value of the vulnerable query param, header, cookie param,
      # or form param.
      #
      # @return [String, nil]
      #
      def original_value
        if @query_param
          @url.query_params[@query_param]
        elsif @header_name
          @headers[@header_name] if @headers
        elsif @cookie_param
          @cookie[@cookie_param] if @cookie
        elsif @form_param
          @form_data[@form_param] if @form_data
        end
      end

      #
      # Returns a random value.
      #
      # @param [Integer] length
      #   The desired length of the String.
      #
      # @return [String]
      #   The random value.
      #
      def random_value(length=4)
        Chars::ALPHA.random_string(length)
      end

      #
      # Determines if the {#url} is vulnerable.
      #
      # @return [Boolean]
      #   Indicates whether the URL is vulnerable.
      #
      # @abstract
      #
      def vulnerable?
        raise(NotImplementedError,"#{self.inspect} did not implement ##{__method__}")
      end

      #
      # Converts the web vulnerability into a String.
      #
      # @return [String]
      #   The String form of {#url}.
      #
      def to_s
        @url.to_s
      end

      #
      # Converts the HTTP request to a `curl` command.
      #
      # @param [#to_s] payload
      #   The optional payload to include in the `curl` command.
      #
      # @return [String]
      #
      def to_curl(payload='PAYLOAD')
        payload = encode_payload(payload)

        HTTPRequest.new(
          @url, request_method: @request_method,
                user:           @user,
                password:       @password,
                user_agent:     @user_agent,
                referer:        @referer,
                query_params:   exploit_query_params(payload),
                cookie:         exploit_cookie(payload),
                headers:        exploit_headers(payload),
                form_data:      exploit_form_data(payload)
        ).to_curl
      end

      #
      # Converts the HTTP request to a raw HTTP request.
      #
      # @param [#to_s] payload
      #   The optional payload to include in the HTTP request.
      #
      # @return [String]
      #
      def to_http(payload='PAYLOAD')
        payload = encode_payload(payload)

        HTTPRequest.new(
          @url, request_method: @request_method,
                user:           @user,
                password:       @password,
                user_agent:     @user_agent,
                referer:        @referer,
                query_params:   exploit_query_params(payload),
                cookie:         exploit_cookie(payload),
                headers:        exploit_headers(payload),
                form_data:      exploit_form_data(payload)
        ).to_http
      end

    end
  end
end
