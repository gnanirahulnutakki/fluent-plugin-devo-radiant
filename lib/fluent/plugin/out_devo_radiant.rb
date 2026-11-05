# frozen_string_literal: true

# Copyright 2016 Acquia, Inc.
# Copyright 2016-2019 t.e.morgan.
# Copyright 2021 JMC
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

require 'msgpack'
require 'socket'
require 'time'
require 'fluent/plugin/output'
require 'fluent/plugin/formatter_json'
require 'fluent/msgpack_factory'
require 'fluent_plugin_devo_radiant/syslog_tls/logger'
require_relative 'devo_radiant_constants'

module Fluent
  module Plugin
    class DevoRadiantOutput < Output
      Fluent::Plugin.register_output('devo_radiant', self)
      Fluent::Plugin.register_output('devo', self)

      helpers :inject, :formatter, :compat_parameters

      DEFAULT_FORMAT_TYPE = 'json'
      TLS_MIN_VERSIONS = FluentPluginDevoRadiant::SyslogTls::SSLTransport::TLS_MIN_VERSIONS.keys.freeze
      Utf8 = FluentPluginDevoRadiant::SyslogTls::Utf8
      Severity = FluentPluginDevoRadiant::SyslogTls::Severity
      CONTENT_KEYS = %w[content message payload body log _raw].freeze
      LEVEL_KEYS = %w[loglevel status severity level syslog.severity log_level log.level @l severitytext lvl levelname].freeze
      TEXT_LEVEL_PATTERN = /\A\[?\d{4}-\d{1,2}-\d{1,2}[T ]
        \d{1,2}:\d{2}(?::\d{2})?(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\]?\s+
        (?:\[[^\]\r\n]{0,128}\]\s+)?
        (TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|SEVERE|FATAL|CRITICAL)\b/x.freeze

      config_param :host, :string
      config_param :port, :integer
      config_param :idle_timeout, :integer, default: nil
      config_param :ca_cert, :string, default: 'system'
      config_param :verify_cert_name, :bool, default: true
      config_param :token, :string, default: nil, secret: true
      config_param :client_cert, :string, default: nil
      config_param :client_key, :string, default: nil, secret: true
      config_param :client_key_passphrase, :string, default: nil, secret: true
      config_param :hostname, :string, default: nil
      config_param :facility, :string, default: 'LOCAL0'
      config_param :tls_min_version, :enum, list: TLS_MIN_VERSIONS, default: :'TLSv1_2'
      config_param :tls, :bool, default: true
      config_param :auto_severity, :bool, default: true
      config_param :inject_timestamp, :bool, default: true
      config_param :timestamp_key, :string, default: '@timestamp'
      config_param :sanitize_tag, :bool, default: true

      SYSLOG_HEADERS = %i[severity facility hostname app_name procid msgid].freeze

      SYSLOG_HEADERS.each do |key_name|
        config_param :"#{key_name}_key", :string, default: nil
      end

      config_section :buffer do
        config_set_default :chunk_keys, ['tag']
      end

      config_section :format do
        config_set_default :@type, DEFAULT_FORMAT_TYPE
      end

      attr_accessor :formatter

      def initialize
        super
        @loggers = {}
        @loggers_mutex = Mutex.new
        @closing = false
        @tag_warnings = {}
        @tag_warnings_mutex = Mutex.new
      end

      def configure(conf)
        conf['format'] = conf['output_type'] if conf['output_type'] && !conf['format']
        compat_parameters_convert(conf, :inject, :formatter)

        super

        @hostname ||= Socket.gethostname.split('.').first
        @mappings = {}
        SYSLOG_HEADERS.each do |key_name|
          conf_key = "#{key_name}_key"
          @mappings[key_name] = conf[conf_key] if conf.key?(conf_key)
        end

        @formatter = formatter_create(conf: conf.elements('format').first, default_type: DEFAULT_FORMAT_TYPE)
        @json_format = @formatter.is_a?(Fluent::Plugin::JSONFormatter)

        if token || procid_key || msgid_key
          log.warn 'token, procid_key and msgid_key are ignored by this syslog format'
        end
        if !tls
          log.warn 'TLS is disabled; traffic is unencrypted plain TCP'
        elsif peer_verification_disabled?
          log.warn 'TLS peer and hostname verification are disabled because ca_cert is false'
        elsif !verify_cert_name
          log.warn 'TLS hostname verification is disabled because verify_cert_name is false'
        end
      end

      def shutdown
        close_loggers
        super
      end

      def close
        close_loggers
        super
      end

      def close_loggers
        loggers = @loggers_mutex.synchronize do
          @closing = true
          current = @loggers.values
          @loggers = {}
          current
        end
        loggers.each(&:close)
      end

      def prefer_buffered_processing
        true
      end

      def formatted_to_msgpack_binary?
        true
      end

      def multi_workers_ready?
        true
      end

      def format(tag, time, record)
        record = inject_values_to_record(tag, time, record)
        Fluent::MessagePackFactory.msgpack_packer.pack([time, record]).full_pack
      end

      def write(chunk)
        tag = chunk.metadata.tag
        raise 'buffer chunk is missing tag metadata' unless tag

        chunk.msgpack_each do |time, record|
          send_record(tag, time, record)
        end
      end

      # Compatibility path for explicitly non-buffered operation. Errors are
      # intentionally allowed to escape so a failed send is never reported as
      # successful.
      def process(tag, event_stream)
        event_stream.each do |time, record|
          send_record(tag, time, inject_values_to_record(tag, time, record))
        end
      end

      def logger(tag)
        cache_key = [fluentd_worker_id, tag]
        cached_logger = @loggers_mutex.synchronize do
          raise IOError, 'Devo output is closing' if @closing

          @loggers[cache_key]
        end
        return cached_logger if cached_logger && !cached_logger.closed?

        candidate = new_logger(tag)
        selected = @loggers_mutex.synchronize do
          raise IOError, 'Devo output is closing' if @closing

          cached_logger = @loggers[cache_key]
          if cached_logger.nil? || cached_logger.closed?
            @loggers[cache_key] = candidate
          else
            cached_logger
          end
        end
        selected
      ensure
        candidate.close if candidate && !candidate.equal?(selected)
      end

      def new_transport(transport_class = FluentPluginDevoRadiant::SyslogTls::SSLTransport)
        transport_class.new(
          host,
          port,
          idle_timeout: idle_timeout,
          ca_cert: ca_cert,
          client_cert: client_cert,
          client_key: client_key,
          client_key_passphrase: client_key_passphrase,
          tls: tls,
          verify_cert_name: verify_cert_name,
          tls_min_version: tls_min_version,
          max_retries: 3
        )
      end

      def new_logger(tag)
        transport = new_transport
        syslog_logger = FluentPluginDevoRadiant::SyslogTls::Logger.new(transport, token)
        syslog_logger.facility(facility)
        syslog_logger.hostname(hostname)
        syslog_logger.app_name(tag)
        syslog_logger
      rescue StandardError
        transport&.close
        raise
      end

      private

      def peer_verification_disabled?
        ca_cert == false || ca_cert == 'false'
      end

      def send_record(tag, time, record)
        record = Utf8.value(record)
        event_time = time.is_a?(Fluent::EventTime) ? Time.at(time.sec, time.nsec, :nanosecond) : Time.at(time)
        if inject_timestamp && !record.key?(timestamp_key)
          record[timestamp_key] = event_time.getutc.iso8601(3)
        end
        severity = record_severity(record)
        message = Utf8.string(@formatter.format(tag, time, record)).sub(/[\r\n]+\z/, '')
        message = message.gsub(/\r\n|\r|\n/) { '\\n' } unless @json_format
        logger(tag).log(severity, message, time: event_time) do |header|
          @mappings.each do |name, record_key|
            next if %i[severity procid msgid].include?(name)

            header.public_send(:"#{name}=", record[record_key]) unless record[record_key].nil?
          end
          header.hostname = Utf8.header_token(header.hostname || hostname)
          header.app_name = devo_tag(record[app_name_key] || tag)
        end
      end

      def record_severity(record)
        explicit = record[severity_key] if severity_key
        return severity_name(explicit) unless explicit.nil?
        return 'INFO' unless auto_severity

        present = {}
        record.each do |key, value|
          normalized_key = Utf8.string(key).downcase
          present[normalized_key] = value unless value.nil? || present.key?(normalized_key)
        end
        level_key = LEVEL_KEYS.find { |key| present.key?(key) }
        return severity_name(present[level_key]) if level_key

        content_key = CONTENT_KEYS.find { |key| present.key?(key) }
        if content_key
          text = Utf8.string(present[content_key].to_s.byteslice(0, 256))
          match = TEXT_LEVEL_PATTERN.match(text)
          return severity_name(match[1]) if match
        end
        result = present['resultcode']
        result = result.strip.to_i if result.is_a?(String) && /\A[0-9]+\z/.match?(result.strip)
        return 'INFO' unless result.is_a?(Integer)

        case result
        when 0, 5, 6, 10, 14 then 'INFO'
        when 1, 51, 52, 53, 54, 80 then 'ERR'
        else 'WARN'
        end
      end

      def severity_name(value)
        %w[EMERG ALERT CRIT ERR WARN NOTICE INFO DEBUG][Severity.normalize(value)]
      end

      def devo_tag(value)
        original = Utf8.string(value)
        cleaned = Utf8.header_token(original)
        if sanitize_tag
          cleaned = cleaned.gsub(/[^A-Za-z0-9.]/, '').split('.').reject(&:empty?).join('.')
        end
        warnings = @tag_warnings_mutex.synchronize do
          next [] if @tag_warnings.key?(original)

          @tag_warnings[original] = true
          messages = []
          messages << "Devo tag changed: #{original.inspect} -> #{cleaned.inspect}" if original != cleaned
          levels = cleaned.split('.', -1)
          if !(2..6).cover?(levels.length) || levels.any?(&:empty?) || cleaned.length > 50
            messages << "Devo tag outside 2-6 nonempty levels or 50 characters: #{cleaned.inspect}; sending anyway"
          end
          messages
        end
        warnings.each { |warning| log.warn warning }
        cleaned
      end
    end
  end
end
