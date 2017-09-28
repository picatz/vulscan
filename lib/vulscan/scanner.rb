module Vulscan
  class Scanner
    def initialize(host)
      @host = host
      @profiles = {}
    end

    def host
      @host
    end

    def profile=(profile)
      @profiles[profile] = Vulscan::Profile.new(profile)
      profiles
    end

    def profiles=(profiles)
      profiles.each do |prof|
        self.profile = prof
      end
    end

    def profiles
      return @profiles unless block_given?
      @profiles.each { |profile| yield profile }
    end

    def test(port:, send: false, recv: 1024, timeout: 5, string:)
      socket = TCPSocket.new(host, port)
      response = false
      Timeout.timeout(timeout) do 
        socket.print(send) if send
        response = socket.recv(recv)
        socket.close
      end
      return nil unless socket && response
      socket.close if socket && !socket.closed?
      return true if response == string
    rescue => errr
      nil
    end

    def scan
      profiles do |_, profile|
        profile.data.each do |port, data|
          next if port == "name" || port == "references"
          if test(port: port, send: data["send"] || false, recv: data["send"] || 1024, string: data["vulnerable_string"]) 
            data = { host: @host, port: port, profile: profile.file }
            data[:name] = profile.name if profile.name?
            data[:references] = profile.references if profile.references?
            yield data
          end
        end
      end
    end
  end
end
