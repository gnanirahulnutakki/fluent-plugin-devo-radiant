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

module FluentPluginDevoRadiant
  module SyslogTls
    module LookupFromConst
      def setup_constants(destination)
        constants.each do |priority|
          value = const_get(priority)

          destination[priority] = value
          destination[priority.downcase] = value

          destination[:"LOG_#{priority}"] = value
          destination[:"LOG_#{priority.to_s.downcase}"] = value
          const_set(:"LOG_#{priority}", value)

          destination[priority.to_s] = value
          destination[priority.to_s.downcase] = value

          destination[value] = value
          destination[value.to_s] = value
        end
      end
    end
  end
end
