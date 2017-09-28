require "pry"
require "socket"
require "timeout"
require "command_lion"
require "json"
require "vulscan/version"
require "vulscan/profile"
require "vulscan/scanner"

module Vulscan

  CommandLion::App.run do

    name "Vulscan"


    command :scan do
      description "Scan targets to assess vulnerabilities."
      flags do
        short "-s"
        long  "--scan"
      end

      before do
        unless options[:hosts].arguments?
          puts "No host(s) given!"
          exit 1
        end
        unless options[:profiles].arguments?
          puts "No profile(s) given!"
          exit 1
        end
      end

      action do
        scanners = []
        options[:hosts].arguments.each do |host|
          scanner = Vulscan::Scanner.new(host)
          scanner.profiles = options[:profiles].arguments
          scanners << scanner
        end
        scanners.each do |scanner|
          scanner.scan do |result|
            puts result
          end
        end
      end

      option :hosts do
        description "Use specific host(s)."
        type :strings
        flags do
          short "-h"
          long  "--hosts"
        end
      end

      option :profiles do
        description "Use specific profile(s)."
        type :strings
        flags do
          short "-p"
          long  "--profiles"
        end
      end
    end

    command :create_profile do
      flags do
        short "-c"
        long  "--create-profile"
      end
      type :string
      before do
        if File.file?(argument)
          puts "File already exists!" 
          exit 1
        end
      end
      description "Create a base profile."
      action do
        File.open(argument, 'w+') { |f| f.write(JSON.pretty_generate({"vulnerabilities" => {}})) }
        profile = Vulscan::Profile.new(argument)
        profile.name = options[:name].arguments if options[:name].arguments?
        profile.references = options[:references].arguments if options[:references].arguments?
        profile.save(argument)
      end
      after do
        puts "Created profile #{argument}"
        exit 0
      end
      option :name do
        flag "--name"
        type :string
        description "Name to associate with profile."
      end
      option :references do
        flag "--references"
        type :strings
        description "References to asociate with profile to use later."
      end
    end

    command :append_to_profile do
      flags do
        short "-a"
        long  "--append-to-profile"
      end
      description "Append information to profile(s)."
      type :string
      before do
        puts "No port selected!"    unless options[:port].arguments?
        puts "No string selected!"  unless options[:string].arguments?
        puts "No profile selected!" unless arguments?
      end

      action do
        begin
          profile = Vulscan::Profile.new(argument)
          profile.add(port: options[:port].argument, 
                      mesg: options[:message].argument || false,
                      send: options[:send].argument || false, 
                      recv: options[:recv].argument || false, 
                      timeout: options[:timeout].argument || false, 
                      vulnerable_string: options[:string].argument)
          profile.save(argument)
        rescue => e
          puts "Unable to successfully append to profile #{argument}!\n#{e}"
        end
      end

      option :port do
        flag "--port"
        type :integer
        description "Port to associate string with."
      end

      option :string do
        flag "--string"
        type :string
        description "Vulnerable string to associate port with."
      end

      option :send do
        flag "--send"
        type :string
        description "Send custom data after connecting."
      end

      option :recv do
        flag "--recv"
        type :integer
        default 1024
        description "Recieve a custom ammount of data back."
      end

      option :timeout do
        flag "--timeout"
        type :integer
        default 5
        description "Custom timeout for connection in seconds."
      end

      option :message do
        flag "--message"
        type :string
        description "Custom vulnerability message to optionally include."
      end
    end

  end

end
