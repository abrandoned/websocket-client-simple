require 'thread'

module WebSocket
  module Client
    module Simple

      def self.connect(url, options={})
        client = ::WebSocket::Client::Simple::Client.new
        yield client if block_given?
        client.connect url, options
        return client
      end

      class Client
        include EventEmitter
        attr_reader :url, :handshake, :message_queue

        MS_2 = (1/500.0)

        def initialize
          @message_queue = ::Queue.new
        end

        def connect(url, options={})
          return if @socket
          @url = url
          uri = URI.parse url
          @socket = TCPSocket.new(uri.host,
                                  uri.port || (uri.scheme == 'wss' ? 443 : 80))
          @socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
          if ['https', 'wss'].include? uri.scheme
            ssl_context = options[:ssl_context] || begin
              ctx = OpenSSL::SSL::SSLContext.new
              ctx.ssl_version = options[:ssl_version] || 'SSLv23'
              ctx.verify_mode = options[:verify_mode] || OpenSSL::SSL::VERIFY_NONE #use VERIFY_PEER for verification
              cert_store = OpenSSL::X509::Store.new
              cert_store.set_default_paths
              ctx.cert_store = cert_store
              ctx
            end

            @socket = ::OpenSSL::SSL::SSLSocket.new(@socket, ssl_context)
            @socket.connect
          end

          @handshake = ::WebSocket::Handshake::Client.new :url => url, :headers => options[:headers]
          @handshaked = false
          @pipe_broken = false
          @closed = false
          once :__close do |err|
            close
            emit :close, err
          end

          handshake
        end

        def send_data(data, opt={:type => :text})
          return if !@handshaked || @closed
          @thread ||= poll # utilize the polling interface, could probably be split into another class

          write_data(data, opt)
        end

        # Returns all responses that have been accepted
        def send_data_and_wait(data, timeout, opt = { :type => :text })
          return [] if !@handshaked || @closed

          response_data = []
          write_data(data, opt)
          pull_next_message_off_of_socket(@socket, timeout)
          pull_next_message_off_of_socket(@socket, MS_2) # 2ms penalty to check for additional messages

          if message_queue.length > 0
            message_queue.length.times do
              response_data << message_queue.pop
            end
          end

          response_data
        end

        def close
          return if @closed

          send_data nil, :type => :close if !@pipe_broken
          emit :__close
        ensure
          @closed = true
          @socket.close if @socket
          @socket = nil
          Thread.kill @thread if @thread
        end

        def open?
          @handshake.finished? and !@closed
        end

      private

        def handshake
          @socket.write @handshake.to_s

          while !@handshaked
            begin
              read_sockets, _, _ = IO.select([@socket], nil, nil, 10)

              if read_sockets && read_sockets[0]
                @handshake << @socket.read_nonblock(1024)

                if @socket.respond_to?(:pending) # SSLSocket
                  @handshake << @socket.read(@socket.pending) while @socket.pending > 0
                end

                @handshaked = @handshake.finished?
              end
            rescue IO::WaitReadable
              retry
            rescue IO::WaitWritable
              IO.select(nil, [socket])
              retry
            end
          end
        end

        def poll
          return Thread.new(@socket) do |socket|
            emit :open

            while !@closed do
              pull_next_message_off_of_socket(socket)

              message_queue.length.times do
                emit :message, message_queue.pop
              end
            end
          end
        end

        def pull_next_message_off_of_socket(socket, timeout = 10, last_frame = nil)
          read_sockets, _, _ = IO.select([socket], nil, nil, timeout)

          if read_sockets && read_sockets[0]
            frame = last_frame || ::WebSocket::Frame::Incoming::Client.new

            begin
              frame << socket.read_nonblock(1024)

              if socket.respond_to?(:pending)
                frame << socket.read(socket.pending) while socket.pending > 0
              end

              if msg = frame.next
                message_queue << msg
                pull_next_message_off_of_socket(socket, MS_2) # 2ms penalty for new frames
              else
                pull_next_message_off_of_socket(socket, timeout, frame)
              end
            rescue IO::WaitReadable
              IO.select([socket])
              retry
            rescue IO::WaitWritable
              IO.select(nil, [socket])
              retry
            rescue => e
              emit :error, e
            end
          end
        end

        def write_data(data, opt)
          frame = ::WebSocket::Frame::Outgoing::Client.new(:data => data, :type => opt[:type], :version => @handshake.version)

          begin
            @socket.write_nonblock(frame.to_s)
          rescue IO::WaitReadable
            IO.select([@socket]) # OpenSSL needs to read internally
            retry
          rescue IO::WaitWritable, Errno::EINTR
            IO.select(nil, [@socket])
            retry
          rescue Errno::EPIPE => e
            @pipe_broken = true
            emit :__close, e
          end
        end
      end
    end
  end
end
