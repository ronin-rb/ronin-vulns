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

require_relative 'printing'
require_relative '../importer'

require 'ronin/db/cli/database_options'
require 'ronin/db/cli/printing'

module Ronin
  module Vulns
    class CLI
      #
      # Mixin module which adds the ability to import web vulns into the
      # [ronin-db] database.
      #
      # [ronin-db]: https://github.com/ronin-rb/ronin-db#readme
      #
      # @since 0.2.0
      #
      module Importable
        include DB::CLI::Printing
        include Printing

        #
        # Includes `Ronin::DB::CLI::DatabaseOptions` into the including command
        # class.
        #
        # @param [Class<Command>] command
        #   The command class including {Importable}.
        #
        def self.included(command)
          command.include DB::CLI::DatabaseOptions
        end

        #
        # Imports a web vulnerability into the [ronin-db] database.
        #
        # [ronin-db]: https://github.com/ronin-rb/ronin-db#readme
        #
        # @param [WebVuln] vuln
        #   The web vulnerability to import.
        #
        def import_vuln(vuln)
          Importer.import(vuln)

          vuln_type  = vuln_type(vuln)
          param_type = vuln_param_type(vuln)
          param_name = vuln_param_name(vuln)

          if (param_type && param_name)
            log_info "Imported #{vuln_type} vulnerability on URL #{vuln.url} and #{param_type} '#{param_name}'"
          else
            log_info "Imported #{vuln_type} vulnerability on URL #{vuln.url}"
          end
        end
      end
    end
  end
end
