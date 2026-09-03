# frozen_string_literal: true

# Copyright 2016 Acquia, Inc.
# Copyright 2016-2019 t.e.morgan.
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

require 'openssl'
require 'rbconfig'
require 'socket'

module FluentPluginDevoRadiant
  module SyslogTls
    class SSLTransport
      CONNECT_TIMEOUT = 10
      WRITE_TIMEOUT = 5

      TLS_MIN_VERSIONS = {
        :'TLSv1_2' => OpenSSL::SSL::TLS1_2_VERSION
      }.tap do |versions|
        versions[:'TLSv1_3'] = OpenSSL::SSL::TLS1_3_VERSION if defined?(OpenSSL::SSL::TLS1_3_VERSION)
      end.freeze

      attr_accessor :socket
      attr_reader :host, :port, :idle_timeout, :ca_cert, :client_cert, :client_key,
                  :verify_cert_name, :tls_min_version
      attr_writer :retries

      def initialize(host, port, idle_timeout: nil, ca_cert: 'system', client_cert: nil,
                     client_key: nil, verify_cert_name: true, tls_min_version: :'TLSv1_2',
                     max_retries: 1)
        @host = host
        @port = port
        @idle_timeout = idle_timeout
        @ca_cert = ca_cert
        @client_cert = client_cert
        @client_key = client_key
        @verify_cert_name = verify_cert_name
        @tls_min_version = tls_min_version.to_sym
        @retries = max_retries
        @write_mutex = Mutex.new

        raise ArgumentError, "Unsupported minimum TLS version: #{tls_min_version}" unless
          TLS_MIN_VERSIONS.key?(@tls_min_version)

        connect
      end

      def connect
        @socket = get_ssl_connection
        begin
          begin
            @socket.connect_nonblock
          rescue Errno::EAGAIN, Errno::EWOULDBLOCK, IO::WaitReadable
            select_with_timeout(@socket, :connect_read) && retry
          rescue IO::WaitWritable
            select_with_timeout(@socket, :connect_write) && retry
          end
        rescue Errno::ETIMEDOUT
          raise 'Socket timeout during connect'
        end
        @last_write = Time.now if idle_timeout
      end

      def get_tcp_connection
        tcp = nil
        family = Socket::Constants::AF_UNSPEC
        socket_type = Socket::Constants::SOCK_STREAM
        address_info = Socket.getaddrinfo(host, port, family, socket_type, nil, nil, false).first
        _, resolved_port, _, address, family, socket_type = address_info

        begin
          socket_address = Socket.sockaddr_in(resolved_port, address)
          tcp = Socket.new(family, socket_type, 0)
          tcp.setsockopt(Socket::SOL_SOCKET, Socket::Constants::SO_REUSEADDR, false)
          unless RbConfig::CONFIG['host_os'].match?(/mswin|mingw|cygwin/)
            tcp.setsockopt(Socket::SOL_SOCKET, Socket::Constants::SO_REUSEPORT, false)
          end
          tcp.connect_nonblock(socket_address)
        rescue Errno::EINPROGRESS
          select_with_timeout(tcp, :connect_write)
          begin
            tcp.connect_nonblock(socket_address)
          rescue Errno::EISCONN
            # Connected.
          rescue SystemCallError
            tcp.close rescue nil
            raise
          end
        rescue SystemCallError
          tcp.close rescue nil
          raise
        end

        tcp.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, true)
        tcp
      end

      def get_ssl_connection
        tcp = get_tcp_connection
        context = build_ssl_context
        ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp, context)
        ssl_socket.hostname = host
        ssl_socket.sync_close = true
        ssl_socket
      end

      def write(string)
        @write_mutex.synchronize { write_with_retries(string) }
      end

      def do_write(data)
        data = data.dup.force_encoding(Encoding::BINARY)
        loop do
          sent = 0
          begin
            sent = @socket.write_nonblock(data)
          rescue OpenSSL::SSL::SSLError, Errno::EAGAIN, Errno::EWOULDBLOCK, IO::WaitWritable => error
            if error.is_a?(OpenSSL::SSL::SSLError) && error.message !~ /write would block/
              raise error
            end

            select_with_timeout(@socket, :write) && retry
          end

          break if sent >= data.bytesize

          data = data.byteslice(sent, data.bytesize - sent)
        end
      end

      def select_with_timeout(tcp, type)
        arguments = case type
                    when :connect_read
                      [[tcp], nil, nil, CONNECT_TIMEOUT]
                    when :connect_write
                      [nil, [tcp], nil, CONNECT_TIMEOUT]
                    when :write
                      [nil, [tcp], nil, WRITE_TIMEOUT]
                    else
                      raise "Unknown select type #{type}"
                    end
        IO.select(*arguments) || raise("Socket timeout during #{type}")
      end

      def method_missing(method_name, *arguments, &block)
        return super unless @socket.respond_to?(method_name)

        @socket.public_send(method_name, *arguments, &block)
      end

      def respond_to_missing?(method_name, include_private = false)
        @socket.respond_to?(method_name, include_private) || super
      end

      private

      def build_ssl_context
        context = OpenSSL::SSL::SSLContext.new
        context.verify_mode = OpenSSL::SSL::VERIFY_PEER
        context.verify_hostname = verify_cert_name != false
        configure_tls_min_version(context)

        case ca_cert
        when true, 'true', 'system'
          context.cert_store = OpenSSL::X509::Store.new
          context.cert_store.set_default_paths
        when false, 'false'
          context.verify_hostname = false
          context.verify_mode = OpenSSL::SSL::VERIFY_NONE
        when %r{/$}
          context.ca_path = ca_cert
        when String
          context.ca_file = ca_cert
        end

        context.cert = OpenSSL::X509::Certificate.new(File.read(client_cert)) if client_cert
        context.key = OpenSSL::PKey.read(File.read(client_key)) if client_key
        context
      end

      def configure_tls_min_version(context)
        context.min_version = TLS_MIN_VERSIONS.fetch(tls_min_version)
      end

      def write_with_retries(string)
        if idle_timeout
          if (now = Time.now) > @last_write + idle_timeout
            @socket.close rescue nil
            connect
          else
            @last_write = now
          end
        end

        begin
          retry_id ||= 0
          do_write(string)
        rescue StandardError => error
          if (retry_id += 1) < @retries
            @socket.close rescue nil
            connect
            retry
          end
          raise error
        end
      end
    end
  end
end
