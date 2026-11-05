# frozen_string_literal: true

# Copyright 2016 Acquia, Inc.
# Copyright 2016 t.e.morgan.
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

require 'date'

require_relative 'facility'
require_relative 'severity'
require_relative 'utf8'

module FluentPluginDevoRadiant
  module SyslogTls
    NIL_VALUE = ''

    class Header
      attr_accessor :version, :hostname, :app_name, :procid, :msgid
      attr_reader :facility, :severity, :timestamp

      FACILITIES = {}
      SEVERITIES = {}

      Facility.setup_constants(FACILITIES)
      Severity.setup_constants(SEVERITIES)

      def initialize
        @timestamp = Time.now
        @severity = 'INFO'
        @facility = 'LOCAL0'
        @version = 1
        @hostname = NIL_VALUE
        @app_name = NIL_VALUE
        @procid = NIL_VALUE
        @msgid = NIL_VALUE
      end

      def timestamp=(value)
        raise ArgumentError, "Must provide Time object value instead: #{value.inspect}" unless value.is_a?(Time)

        @timestamp = value
      end

      def facility=(value)
        raise ArgumentError, "Invalid facility value: #{value.inspect}" unless FACILITIES.key?(value)

        @facility = value
      end

      def severity=(value)
        @severity = Severity.normalize(value)
      end

      def pri
        FACILITIES[facility] * 8 + SEVERITIES[severity]
      end

      def assemble
        [
          "<#{pri}>#{timestamp.to_datetime.strftime('%b %d %H:%M:%S')}",
          Utf8.header_token(hostname),
          Utf8.header_token(app_name)
        ].join(' ')
      end

      def to_s
        assemble
      end
    end

    class StructuredData
      attr_accessor :id, :data

      def initialize(id)
        @id = id
        @data = {}
      end

      def assemble
        return NIL_VALUE unless id

        parts = [id]
        data.each do |key, value|
          value = value.gsub(/(\"|\]|\\)/) { |match| '\\' + match }
          parts << "#{key}=\"#{value}\""
        end
        "[#{parts.join(' ')}]"
      end

      def to_s
        assemble
      end
    end

    class Message
      attr_accessor :structured_data, :msg
      attr_writer :header

      def initialize
        @msg = ''
        @structured_data = []
      end

      def header
        @header ||= Header.new
      end

      def assemble
        output = [header.to_s]
        message = Utf8.string(msg).sub(/[\r\n]+\z/, '')
        output << message if message.length.positive?
        output.join(' ') + "\n"
      end

      def to_s
        assemble
      end
    end
  end
end
