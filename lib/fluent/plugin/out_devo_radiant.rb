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
require 'fluent/plugin/output'
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

      config_param :host, :string
      config_param :port, :integer
      config_param :idle_timeout, :integer, default: nil
      config_param :ca_cert, :string, default: 'system'
      config_param :verify_cert_name, :bool, default: true
      config_param :token, :string, default: nil, secret: true
      config_param :client_cert, :string, default: nil
      config_param :client_key, :string, default: nil, secret: true
      config_param :hostname, :string, default: nil
      config_param :facility, :string, default: 'LOCAL0'
      config_param :tls_min_version, :enum, list: TLS_MIN_VERSIONS, default: :'TLSv1_2'

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

        if peer_verification_disabled?
          log.warn 'TLS peer and hostname verification are disabled because ca_cert is false'
        elsif !verify_cert_name
          log.warn 'TLS hostname verification is disabled because verify_cert_name is false'
        end
      end

      def shutdown
        loggers = @loggers_mutex.synchronize do
          current = @loggers.values
          @loggers = {}
          current
        end
        loggers.each { |cached_logger| cached_logger.close unless cached_logger.closed? }
        super
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
        [time, record].to_msgpack
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
        @loggers_mutex.synchronize do
          cached_logger = @loggers[cache_key]
          if cached_logger.nil? || cached_logger.closed?
            cached_logger = new_logger(tag)
            @loggers[cache_key] = cached_logger
          end
          cached_logger
        end
      end

      def new_logger(tag)
        transport = FluentPluginDevoRadiant::SyslogTls::SSLTransport.new(
          host,
          port,
          idle_timeout: idle_timeout,
          ca_cert: ca_cert,
          client_cert: client_cert,
          client_key: client_key,
          verify_cert_name: verify_cert_name,
          tls_min_version: tls_min_version,
          max_retries: 3
        )
        syslog_logger = FluentPluginDevoRadiant::SyslogTls::Logger.new(transport, token)
        syslog_logger.facility(facility)
        syslog_logger.hostname(hostname)
        syslog_logger.app_name(tag)
        syslog_logger
      end

      private

      def peer_verification_disabled?
        ca_cert == false || ca_cert == 'false'
      end

      def send_record(tag, time, record)
        severity = if @mappings.key?(:severity)
                     record[@mappings[:severity]] || 'INFO'
                   else
                     'INFO'
                   end

        message = @formatter.format(tag, time, record)
        logger(tag).log(severity, message, time: Time.at(time)) do |header|
          @mappings.each do |name, record_key|
            header.public_send(:"#{name}=", record[record_key]) unless record[record_key].nil?
          end
        end
      end
    end
  end
end
