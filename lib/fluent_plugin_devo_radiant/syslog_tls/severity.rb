# frozen_string_literal: true

# Copyright 2016 Acquia, Inc.
# Copyright 2021 Devo .Inc.
# Copyright 2026 Radiant Logic, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require_relative 'lookup_from_const'
require_relative 'utf8'

module FluentPluginDevoRadiant
  module SyslogTls
    module Severity
      extend LookupFromConst

      EMERG = PANIC = 0
      ALERT = 1
      CRIT = 2
      FATAL = CRITICAL = CRIT
      ERR = ERROR = 3
      SEVERE = ERR
      WARN = WARNING = 4
      NOTICE = 5
      INFO = 6
      INFORMATION = INFORMATIONAL = INFO
      DEBUG = 7
      TRACE = FINE = FINER = FINEST = VERBOSE = DEBUG
      EMERGENCY = EMERG
      NONE = INFO

      def self.normalize(value)
        if value.is_a?(Integer) || value.is_a?(Float)
          return value.to_i if (0..7).cover?(value) && value == value.to_i
        elsif value.is_a?(String) || value.is_a?(Symbol)
          name = Utf8.string(value).strip.upcase
          return name.to_i if /\A[0-7]\z/.match?(name)
          return const_get(name, false) if /\A[A-Z_]+\z/.match?(name) && const_defined?(name, false)
        end
        INFO
      end
    end
  end
end
