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

require_relative 'protocol'
require_relative 'ssl_transport'

module FluentPluginDevoRadiant
  module SyslogTls
    class Logger
      attr_reader :token
      attr_accessor :transport

      def initialize(transport, token = nil)
        @transport = transport
        @token = token
        @default_header = Header.new
        @default_structured_data = StructuredData.new(token)
      end

      def facility(value)
        @default_header.facility = value
      end

      def hostname(value)
        @default_header.hostname = value
      end

      def app_name(value)
        @default_header.app_name = value
      end

      def procid(value)
        @default_header.procid = value
      end

      def closed?
        transport && transport.closed?
      end

      def close
        transport.close
      end

      def log(severity, message, time: nil)
        time ||= Time.now

        syslog_message = Message.new
        syslog_message.structured_data << @default_structured_data
        syslog_message.header = @default_header.dup
        syslog_message.header.severity = severity
        syslog_message.header.timestamp = time

        yield syslog_message.header if block_given?

        syslog_message.msg = message
        transport.write(syslog_message.to_s)
      end
    end
  end
end
