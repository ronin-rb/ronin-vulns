# frozen_string_literal: true
#
# Copyright (c) 2006-2024 Hal Brodigan (postmodern.mod3 at gmail.com)
#
# ronin-support is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ronin-support is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with ronin-support.  If not, see <https://www.gnu.org/licenses/>.
#

require_relative "../../../vulns/url_scanner"

module URI
  #
  # Provides helper methods for HTTP
  #
  # ## Core-Ext Methods
  #
  # * { URI::HTTP#vulns }
  # * { URI::HTTP#has_vulns? }
  #
  # @api public
  #
  class HTTP

    #
    # Return all vulnerabilities found for URI
    #
    # @param [Hash{Symbol => Object}] kwargs
    #   Additional keyword arguments for
    #   {Ronin::Vulns::URLScanner.scan}.
    #
    # @return [Array<LFI, RFI, SQLI, SSTI, ReflectedXSS, OpenRedirect>]
    #   All discovered Web vulnerabilities
    #
    # @example
    #   URI('https://testphp.vulnweb.com/').vulns
    #   # => [#<Ronin::Vulns::RFI: ...>, ...]
    #
    # @see Ronin::Vulns::URLScanner.scan
    #
    def vulns(**kwargs)
      Ronin::Vulns::URLScanner.scan(self, **kwargs)
    end

    #
    # Checks if the URI contains any vulnerabilities
    #
    # @param [Hash{Symbol => Object}] kwargs
    #   Additional keyword arguments for
    #   {Ronin::Vulns::URLScanner.test}.
    #
    # @return [Boolean]
    #
    # @example
    #   URI('https://testphp.vulnweb.com/').has_vulns?
    #   # => true
    #
    # @see Ronin::Vulns::URLScanner.test
    #
    def has_vulns?(**kwargs)
      Ronin::Vulns::URLScanner.test(self, **kwargs) != nil
    end
  end
end
