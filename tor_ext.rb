#!/usr/bin/ruby

require 'base64'
require 'time'
gem 'tor'
require 'tor/control'

# TorExt is what I wish would have been be a part of Tor::Controller

class TorExt < Tor::Controller

  class RouterStatus
    def initialize(nick, idhash, orhash, updated, ip, orport, dirport)
      @nick      = nick
      @idhash    = idhash
      @idhex=Base64.decode64(idhash+"=").unpack("H*").first
      @orhash    = orhash
      @updated   = updated
      @ip        = ip
      @orport    = orport
      @dirport   = dirport
      @ports     = "reject 1-65535"
      @flags     = ""
      @bandwidth = 0
    end

    attr_accessor :nick
    attr_accessor :idhash
    attr_accessor :orhash
    attr_accessor :ip
    attr_accessor :orport
    attr_accessor :dirport
    attr_accessor :flags
    attr_accessor :updated
    attr_accessor :idhex
    attr_accessor :bandwidth
    attr_accessor :ports

    def accept_port_range?(p)
      @ports.find{|a| a[0] <= p[0] && a[1] >= p[1] }
    end

    # find if range r is covered by @ports starting from i
    # return matching i, or false
    # Assumptions: lists are sorter, ranges are merged (no 22-22,23-23, just 22-23)
    def check_range(i,r)
      while i < @ports.size
        if @ports[i][0] > r[0]
          return false
        elsif @ports[i][1] < r[1]
          i += 1
        else
          return i
        end
      end
      false
    end

    def accept_port_ranges?(ranges)
      i=0 # index of @ports that might match next range
      ! ranges.find{|r| !(i=check_range(i,r)) }
    end

  end

  class Reply
    def initialize (code, lines)
      @code = code
      @lines = lines
    end

    attr_accessor :code
    attr_accessor :lines

    def to_s
      "#{code} #{lines.join("\n")}"
    end
  end

  def initialize(options = {}, &block)
    super(options, &block)
    @event_queue=[]
  end

  attr_accessor :event_queue

  # return Reply if command has been executed, otherwise update @event_queue and return nil
  def update
    results = []
    loop do
      line=read_reply
      results << line[4..-1]
      case line[3]
      when ' '
        return Reply.new(line[0..2],results) unless line[0..2] == "650"
        @event_queue.push(*results)
        return nil
      when '-'
      when '+'
        while (r=read_reply) != "." do
          results << r
        end
      else
        raise ParsingError.new(line)
      end
    end
  end

  # return Reply
  def exec_command(command, *args)
    send_command(command, *args)
    r = nil
    begin r=update end while !r
    r
  end

  def close_all_circuits
    r=exec_command("GETINFO","circuit-status")
    r.lines.shift
    r.lines.each { |l| exec_command("CLOSECIRCUIT", $1) if l=~/(\d+) BUILT/ }
  end

  def find_circuit (hops)
    r=exec_command("GETINFO","circuit-status")
    r.lines.shift
    re=Regexp.new("(\\d+) BUILT " + hops.map{|hop| "\\$#{hop}[=~][^, ]+"}.join(",") + " ", "i")
    r.lines.find { |l| l=~re } ? $1 : nil
  end

  def get_routers
    puts "gettings tor directory"
    res=exec_command("GETINFO","ns/all")
    res.lines.shift
    ns=nil
    routers=[]
    loop do
      line=res.lines.shift
      break if line=="OK" or line.nil?
      case line[0]
      when 'r'
        routers << ns unless ns.nil?
        ns_ary=line.scan(/r (\S+) (\S+) (\S+) (\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) (\d+\.\d+\.\d+\.\d+) (\d+) (\d+)/).first
        ns=RouterStatus.new(ns_ary[0], ns_ary[1], ns_ary[2], Time.parse(ns_ary[3]), ns_ary[4], ns_ary[5], ns_ary[6])
      when 's'
        ns.flags     = line.split
        ns.flags.shift
      when 'w'
        ns.bandwidth = line.split('=')[1].to_i
      when 'p'
        ns.ports     = line[2..-1]
      else
        raise ParsingRouters(line)
      end
    end
    routers
  end

  def parse_ports(ports)
    p=ports.split
    case p[0]
    when 'accept'
      res = p[1].split(',').map{|r| r=~/(\d+)-(\d+)/ ? [$1.to_i,$2.to_i] : [r.to_i,r.to_i] }
    when 'reject'
      next_accept = 1
      res =  p[1].split(',').map{|r|
        reject = r=~/(\d+)-(\d+)/ ? [$1.to_i,$2.to_i] : [r.to_i,r.to_i]
        this_accept=next_accept
        next_accept=reject[1]+1
        reject[0] <= this_accept ? nil : [this_accept,reject[0]-1]
      }
      res.compact!
      res << [next_accept,65535] if next_accept<=65535
    else
      raise ParsingPortsError ports
    end
    #TODO Check if ports need merging or sorting. They are not, AFAIK
    res
  end

  class ParsingError < StandardError; end
  class CircuitExtensionError < StandardError; end
  class AttachingStreamError < StandardError; end
  class ParsingRouters < StandardError; end
  class ParsingPortsError < StandardError; end
end

