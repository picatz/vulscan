module Vulscan
  class Profile 
    def initialize(file)
      @file = file
      from_json(file)
    end

    def file
      return nil unless @file
      @file
    end

    def file=(file)
      @file = file
      from_json(file)
    end

    def to_json(pretty: false)
      return JSON.pretty_generate(@data) if pretty 
      @data.to_json
    end

    def from_json(file)
      @data = JSON.parse(File.read(file))
    end

    def save(location = @file)
      File.open(location, 'w+') { |f| f.write(to_json(pretty: true)) } 
    end

    def save!
      save
    end

    def backup(location = @file + ".bak")
      File.open(location, 'w+') { |f| f.write(to_json(pretty: true)) }
    end

    def backup!
      backup
    end

    def data
      @data = { "vulnerabilities" => {} } unless @data
      @data["vulnerabilities"] 
    end
  
    def port?(port)
      data.key?(port)
    end

    def send?(port)
      return false unless port?(port)
      data[port].key?("send")
    end
    
    def recv?(port)
      return false unless port?(port)
      data[port].key?("recv")
    end
  
    def vulnerable_string?(port)
      return false unless port?(port)
      data[port].key?("vulnerable_string")
    end


    def vulnerable_string(port)
      return nil unless port?(port)
      data[port].key?("string")
    end

    def send(port)
      return nil unless send?(port)
      data[port]["send"]
    end

    def recv(port)
      return nil unless recv?(port)
      data[port]["recv"]
    end

    def add(port:, send: false, recv: false, timeout: false, mesg: false, vulnerable_string:)
      raise "Port already been registered in profile!" if port?(port)
      port = port.to_i
      data[port] = {} 
      data[port]["vulnerable_string"] = vulnerable_string 
      data[port]["send"] = send if send
      data[port]["timeout"] = timeout if timeout 
      data[port]["recv"] = recv if recv
      data[port]["message"] = mesg if mesg
    end

    def name=(string)
      data["name"] = string
    end

    def name
      data["name"]
    end

    def name?
      return true if self.name
      false
    end

    def reference=(string)
      data["references"] = [] unless data["references"]
      data["references"] << string
    end

    def references=(strings)
      strings.each do |string|
        self.reference = string
      end
    end
    
    def references
      data["references"]
    end

    def references?
      return false if self.references.empty?
      true
    end

  end
end
