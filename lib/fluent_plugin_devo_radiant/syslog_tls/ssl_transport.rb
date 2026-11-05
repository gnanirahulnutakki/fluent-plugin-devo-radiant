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
                  :verify_cert_name, :tls_min_version, :tls
      attr_writer :retries

      def initialize(host, port, idle_timeout: nil, ca_cert: 'system', client_cert: nil,
                     client_key: nil, verify_cert_name: true, tls_min_version: :'TLSv1_2',
                     max_retries: 1, client_key_passphrase: nil, tls: true)
        @host = host
        @port = port
        @idle_timeout = idle_timeout
        @ca_cert = ca_cert
        @client_cert = client_cert
        @client_key = client_key
        @client_key_passphrase = client_key_passphrase
        @tls = tls
        @closed = false
        @verify_cert_name = verify_cert_name
        @tls_min_version = tls_min_version.to_sym
        @retries = max_retries
        @write_mutex = Mutex.new

        raise ArgumentError, "Unsupported minimum TLS version: #{tls_min_version}" unless
          TLS_MIN_VERSIONS.key?(@tls_min_version)

        connect
      end

      def connect
        raise IOError, 'Transport is closed' if @closed

        last_error = nil
        resolved_addresses.each do |address_info|
          candidate = nil
          begin
            raise IOError, 'Transport is closed' if @closed

            candidate = tls ? get_ssl_connection(address_info) : get_tcp_connection(address_info)
            if tls
              begin
                candidate.connect_nonblock
              rescue IO::WaitReadable
                select_with_timeout(candidate, :connect_read)
                retry
              rescue IO::WaitWritable
                select_with_timeout(candidate, :connect_write)
                retry
              end
            end
            raise IOError, 'Transport is closed' if @closed

            @socket = candidate
            @last_write = Time.now if idle_timeout
            return
          rescue StandardError => error
            candidate.close if candidate && !candidate.closed?
            raise if @closed

            last_error = error
          end
        end
        raise(last_error || SocketError.new('No addresses resolved'))
      end

      def resolved_addresses
        Socket.getaddrinfo(host, port, Socket::AF_UNSPEC, Socket::SOCK_STREAM, nil, nil, false)
      end

      def get_tcp_connection(address_info = nil)
        addresses = address_info ? [address_info] : resolved_addresses
        last_error = nil
        addresses.each do |address_info|
          tcp = nil
          begin
            _, resolved_port, _, address, family, socket_type = address_info
            socket_address = Socket.sockaddr_in(resolved_port, address)
            tcp = Socket.new(family, socket_type, 0)
            tcp.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, false)
            unless RbConfig::CONFIG['host_os'].match?(/mswin|mingw|cygwin/)
              tcp.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, false)
            end
            begin
              tcp.connect_nonblock(socket_address)
            rescue IO::WaitWritable
              select_with_timeout(tcp, :connect_write)
              error = tcp.getsockopt(Socket::SOL_SOCKET, Socket::SO_ERROR).int
              raise SystemCallError.new('connect', error) unless error.zero?
            end
            tcp.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, true)
            return tcp
          rescue StandardError => error
            tcp&.close
            last_error = error
          end
        end
        raise(last_error || SocketError.new('No addresses resolved'))
      end

      def get_ssl_connection(address_info = nil)
        tcp = get_tcp_connection(address_info)
        context = build_ssl_context
        ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp, context)
        ssl_socket.sync_close = true
        ssl_socket.hostname = host
        ssl_socket
      rescue StandardError
        ssl_socket&.close
        tcp.close if tcp && !tcp.closed?
        raise
      end

      def closed?
        @closed || @socket.nil? || @socket.closed?
      end

      def close
        @closed = true
        @write_mutex.synchronize { close_socket }
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
          rescue IO::WaitReadable
            select_with_timeout(@socket, :write_read) && retry
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
                    when :write_read
                      [[tcp], nil, nil, WRITE_TIMEOUT]
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
        when String
          if File.directory?(ca_cert)
            context.ca_path = ca_cert
          else
            context.ca_file = ca_cert
          end
        end

        if client_cert
          certificates = File.read(client_cert).scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m)
          raise OpenSSL::X509::CertificateError, 'Client certificate bundle is empty' if certificates.empty?

          context.cert, *chain = certificates.map { |pem| OpenSSL::X509::Certificate.new(pem) }
          context.extra_chain_cert = chain unless chain.empty?
        end
        if client_key
          context.key = OpenSSL::PKey.read(File.read(client_key), @client_key_passphrase) { @client_key_passphrase }
        end
        context
      end

      def configure_tls_min_version(context)
        context.min_version = TLS_MIN_VERSIONS.fetch(tls_min_version)
      end

      def close_socket
        @socket.close if @socket && !@socket.closed?
      end

      def write_with_retries(string)
        raise IOError, 'Transport is closed' if @closed

        retry_id = 0
        begin
          raise IOError, 'Transport is closed' if @closed

          if @socket.nil? || @socket.closed? || (idle_timeout && Time.now > @last_write + idle_timeout)
            close_socket
            connect
          end
          do_write(string)
          @last_write = Time.now if idle_timeout
        rescue StandardError
          close_socket
          retry_id += 1
          retry if !@closed && retry_id < @retries

          raise
        end
      end
    end
  end
end
