=begin

  Show SISO (Simple iSCSI Storage)'s iSCSI connection list.

  Copyright(C) 2012 Makoto KOBARA <makoto.kobara _at_ gmail.com>
 
  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License as
  published by the Free Software Foundation; either version 2 of the
  License, or (at your option) any later version.
 
  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.
 
  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
  02110-1301 USA

=end

require 'socket'
require 'rubygems'
require 'nokogiri'

UNIXSocket.open("/tmp/siso_admin") {|sock|
#  p sock.peeraddr
  sock.send [0x01].pack("c*"), 0
  s = sock.recv(65536)
#  print s
#  print "-----\n"
  doc = Nokogiri::XML(s)
  doc.xpath("//target").each { |target|
    targetname = target.xpath(".//targetname").inner_text
    print "Target: \"#{targetname}\"\n"
    target.xpath(".//session").each { |session|
      tsih = session.xpath(".//tsih").inner_text
      isid = session.xpath(".//isid").inner_text
      print "  Session: ISID=#{isid}, TSIH=#{tsih}\n"
      session.xpath(".//connection").each { |conn|
        cid = conn.xpath(".//cid").inner_text
        address = conn.xpath(".//address").inner_text
        print "    Connection: CID=#{cid}, InitiatorAddress=#{address}\n"
      }
    }
  }
}
