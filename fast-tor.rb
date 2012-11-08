#!/usr/bin/ruby

############
#
# fast-tor.rb v0.1 by Pat Delancey
#
############

<<README

fast-tor.rb is a tor controller routing all user streams through 2 hop circuit
selected for (hopefully) speedy low-latency connectivity.
Beware: anonimity suffers!
To acheve fast connection, user can specify the country where tor routers are
located, their bandwidth, flags, and ports that have to be supported by exits
(less required ports -> more routers to choose from).
fast-tor.rb is using tor gem and reuses/inspired by
http://github.com/dirtyfilthy/tormux.rb

## INSTALLATION

% [sudo] gem install tor
% chmod +x fast-tor.rb
uncomment the ControlPort line in your /etc/tor/torrc and restart tor. You may
also want to add a password to your tor controller service. To do this, run
% tor --hash-password YOURPASS
and copy/paste the resulting hash into your torrc with a line like:
HashedControlPassword 16:223024AD08B5A268596F1CF0142EFCA99C91508129231FD5FB5CB460C8

## USAGE

fast-tor.rb [options]
Example: fast-tor.rb -p \"SuperSecretPassword\" -c us -b 1000
Make sure the quotes are passed as part of the string if specifying password,
do not pass quotes if specifying cookie.

## OPTIONS

    -a, --authentificate PASS        password (quoted) or cookie (unquoted) for tor control
    -t, --tor-control IP:PORT        tor control port to connect to (default 127.0.0.1:9051)
    -c, --country COUNTRY_CODE       limit routers to those in specified country (no restriction by default)
    -b, --bandwidth BANDWIDTH        limit routers by bandwidth (default is 0, but Fast flag is enabled)
    -f, --flags FLAGS                limit routers by specified flags (default is Fast Valid Running)
    -p, --ports PORTS                limit exits to those accepting specified ports (default is "accept 80,443,1024-65535")
                                     or rejecting no more than specified (default is "reject 1-79,81-442,444-1023")
    -r, --routers ROUTERS            try to connect to specified routers (by default - connect to random)
    -d, --disconnect                 disconnect existing circuits on startup
    -h, --help                       print this

README

require 'optparse'
require_relative 'tor_ext'

class FastTorCtl < TorExt

  def initialize(options = {}, &block)
    super(options, &block)
    @country = options[:country]
    @bandwidth = options[:bandwidth]
    @flags = options[:flags] || %w(Fast Valid Running)
    @required_ports = parse_ports (options[:ports] || "accept 80,443,1024-65535")
    @routers = options[:routers]
    @exits = []
    @guards = []
    @circuit_status = :none
    @curcuit_id = 0

    trap("INT"){ shutdown }
    exec_command "SETCONF maxcircuitdirtiness=99999999"
    exec_command "SETCONF __LeaveStreamsUnattached=1"
    exec_command "SETCONF EnforceDistinctSubnets=0"
    exec_command "SETCONF UseEntryGuards=0"
  end

  # tidy up after ourselves
  def shutdown
    puts "shutting down"
    exec_command "RESETCONF __LeaveStreamsUnattached"
    exec_command "RESETCONF maxcircuitdirtiness"
    exec_command "RESETCONF EnforceDistinctSubnets"
    exec_command "RESETCONF UseEntryGuards"
    puts "config restored"
    quit
  end

  def select_routers
    good_ones=get_routers.select{|r|
      (!@bandwidth  || r.bandwidth >= @bandwidth) &&
      (r.flags & @flags).size == @flags.size &&
      (!@country || exec_command("GETINFO", "ip-to-country/#{r.ip}").
          lines[0].split('=')[1]==@country)
    }
    good_ones.each_index {|i|
      good_ones[i].ports = parse_ports good_ones[i].ports
    }
    @exits=good_ones.select{|r|
      r.flags.include?("Exit") && r.accept_port_ranges?(@required_ports)
    }
    @guards=good_ones.select{|r|
      r.flags.include?("Guard")
    } - @exits
    puts "#{@exits.count} exits & #{@guards.count} guards found"
    if @exits.count == 0 || @guards.count == 0
      puts "no good circuit"
      shutdown
      puts "bye!"
      exit
    end
  end

  def get_circuit
    if !@routers
      f=@guards.sample
      x=@exits.sample
    else
      f=@guards.find{|g| g.nick==@routers[0]}
      x=@exits.find{|e| e.nick==@routers[1]}
    end
    raise "failed to find suitable routers" if x.nil? || f.nil?
    if (@circuit_id = find_circuit [f.idhex,x.idhex])
      @circuit_status = :built
      puts "attached to existing circuit #{nc} #{f.nick},#{x.nick}"
    else
      r=exec_command("EXTENDCIRCUIT 0 $#{f.idhex},$#{x.idhex}")
      raise CircuitExtensionError.new(
        "failed to extend circuit '#{f.nick},#{x.nick}'") unless
          r.lines[0]=~/EXTENDED (\S*)/
      @circuit_id = $1
      @circuit_status = :extended
      puts "launched circuit #@circuit_id #{f.nick},#{x.nick}"
    end
  end

  def attach_stream(stream_id, circuit_id,  debug)
    r = exec_command("ATTACHSTREAM",stream_id,circuit_id)
    return if r.code=="250" || r.code=='552' && r.lines[0] =~ /Unknown stream/  ||
              r.code=='551' # && debug=~/STREAM \d+ NEW 0 \[[0-9A-F:]+\]:\d+/i
    if r.code=='552' && r.lines[0] =~ /Unknown circuit/ && circuit_id != 0
      @circuit_status = :gone
      puts "our circuit #{circuit_id} is gone, now where is it?"
      attach_stream(stream_id, 0,  debug)
    else
      puts "failed to attach stream '#{r}' \n #{debug}"
      shutdown
      puts "bye!"
      exit
    end
  end

  def process_events
    while(e=@event_queue.shift) do
      case e
      when /STREAM (\d+) NEW 0 \S+ \S+ PURPOSE=(\S+)/
        stream_id = $1
        case $2
        when /USER/
          if @circuit_status == :built
            attach_stream(stream_id, @circuit_id, e)
          else
            puts "our stream is not available, routing by tor"
            attach_stream(stream_id, 0, e)
          end
        when /DNS_REQUEST/
          attach_stream(stream_id, 0, e)
        else
          # nothing else to do, really
        end

      when /STREAM (\d+) DETACHED \d+ (\S+) REASON=(?:TIMEOUT|END REMOTE_REASON=EXITPOLICY|END REMOTE_REASON=NOROUTE)/
        attach_stream($1, 0, e)
        puts "letting tor route to #{$2}"

      when /CIRC #@circuit_id BUILT/
        @circuit_status = :built
        puts "built circuit #@circuit_id. All Systems Go!"

      when /CIRC #@circuit_id (?:CLOSED|FAILED)/
        @circuit_status = :closed_failed
        puts "our circuit #@circuit_id is dead, building new"
        get_circuit

      else
        # nothing else to do, really
      end
    end
  end

  def main_loop
    loop do
      raise "Unexpected results while updating" if update
      process_events
    end
  rescue IOError, EOFError, Errno::ECONNABORTED
    puts "main loop is done"
  end

end

options={}
opts=OptionParser.new do |opts|

  opts.banner = <<-eos
fast-tor v0.1 -- route tor user traffic through fast circuit
Usage: ./fast-tor.rb [options]
  eos
  opts.separator ""
  opts.separator "Options:"
  opts.on("-a", "--authentificate PASS", "password (quoted) or cookie (unquoted) for tor control") do |pass|
    options[:cookie] = pass
  end

  opts.on("-t", "--tor-control IP:PORT", "tor control port to connect to (default 127.0.0.1:9051)") do |t|
    options[:host]=t.split(":")[0]
    options[:port]=t.split(":")[1]
  end

  opts.on("-c", "--country COUNTRY_CODE", "limit routers to those in specified country (no restriction by default)") do |c|
    options[:country] = c
  end

  opts.on("-b", "--bandwidth BANDWIDTH", "limit routers by bandwidth (default is 0, but Fast flag is enabled)") do |b|
    options[:bandwidth] = b.to_i
  end

  opts.on("-f", "--flags FLAGS", "limit routers by specified flags (default is Fast Valid Running)") do |f|
    options[:flags]=f.split
  end

  opts.on("-p", "--ports PORTS", "limit exits to those accepting specified ports (default is \"accept 80,443,1024-65535\")\n"+
     "                                     or rejecting no more than specified (default is \"reject 1-79,81-442,444-1023\")") do |p|
    options[:ports]=p
  end

  opts.on("-r", "--routers ROUTERS", "try to connect to specified routers (by default - connect to random)") do |r|
    options[:routers]=r.split(',')
  end

  opts.on("-d", "--disconnect", "disconnect existing circuits on startup") do
    options[:disconnect] = true
  end

  opts.on("-h", "--help", "print this") do
    options[:help] = true
  end

end

opts.parse!
if options[:help]
  puts opts
  exit(0)
end

t=FastTorCtl.new options
t.exec_command "SETEVENTS STREAM CIRC"
t.close_all_circuits if options[:disconnect]
t.select_routers
t.get_circuit
t.main_loop
