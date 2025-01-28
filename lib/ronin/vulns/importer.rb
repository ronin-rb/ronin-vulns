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

require 'ronin/db'

module Ronin
  module Vulns
    #
    # Handles importing discovered {WebVuln web vulnerability} objects into
    # [ronin-db].
    #
    # [ronin-db]: https://github.com/ronin-rb/ronin-db#readme
    #
    # ## Examples
    #
    #     require 'ronin/vulns/url_scanner'
    #     require 'ronin/vulns/importer'
    #
    #     Ronin::Vulns::URLScanner.scan(url) do |vuln|
    #       Ronin::Vulns::Importer.import(vuln)
    #     end
    #
    # @since 0.2.0
    #
    module Importer
      #
      # Imports a web vulnerability into database.
      #
      # @param [WebVuln] vuln
      #   The web vulnerability to import.
      #
      # @yield [imported]
      #   If a block is given, it will be passed the imported database records.
      #
      # @yieldparam [Ronin::DB::WebVuln] imported
      #   The imported web vulnerability record.
      #
      # @return [Ronin::DB::WebVuln]
      #   The imported web vuln record.
      #
      def self.import(vuln)
        imported_url = import_url(vuln.url)

        attributes = {
          url:  imported_url,
          type: vuln.class.vuln_type,

          query_param:    vuln.query_param,
          header_name:    vuln.header_name,
          cookie_param:   vuln.cookie_param,
          form_param:     vuln.form_param,
          request_method: vuln.request_method
        }

        case vuln
        when LFI
          attributes[:lfi_os]            = vuln.os
          attributes[:lfi_depth]         = vuln.depth
          attributes[:lfi_filter_bypass] = vuln.filter_bypass
        when RFI
          attributes[:rfi_script_lang]   = vuln.script_lang
          attributes[:rfi_filter_bypass] = vuln.filter_bypass
        when SQLI
          attributes[:sqli_escape_quote]  = vuln.escape_quote
          attributes[:sqli_escape_parens] = vuln.escape_parens
          attributes[:sqli_terminate]     = vuln.terminate
        when SSTI
          attributes[:ssti_escape_type] = vuln.escape_type
        when CommandInjection
          attributes[:command_injection_escape_quote]    = vuln.escape_quote
          attributes[:command_injection_escape_operator] = vuln.escape_operator
          attributes[:command_injection_terminator]      = vuln.terminator
        end

        imported_vuln = DB::WebVuln.transaction do
                          DB::WebVuln.find_or_create_by(attributes)
                        end

        yield imported_vuln if block_given?
        return imported_vuln
      end

      #
      # Imports a URL into the database.
      #
      # @param [URI, String] url
      #   The URL to import.
      #
      # @return [Ronin::DB::URL]
      #   The imported URL record.
      #
      def self.import_url(url)
        DB::URL.transaction do
          DB::URL.find_or_import(url)
        end
      end
    end
  end
end
