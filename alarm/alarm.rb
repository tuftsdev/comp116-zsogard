#Assignment 2
#COMP 116 - Fall 2015
#Zachary Sogard
#alarm.rb

#!/usr/bin/ruby

require 'packetfu'
require 'base64'


$incident_number = 0
def monitor_stream()
	capture = PacketFu::Capture.new(:start => true, :iface => 'wlan0', :promisc => true)
	# stream.show_live()

	capture.stream.each do |p|
		packet = PacketFu::Packet.parse(p)


		#Look for TCP scans
		if (packet.protocol.include?('TCP')) then
			if (packet.tcp_flags.fin == 1 && packet.tcp_flags.urg == 1 && packet.tcp_flags.psh == 1) then
				#XMAS
				$incident_number += 1
				print_alert("XMAS scan", packet.ip_saddr, 'TCP', Base64.encode64(packet.payload))

			elsif (packet.tcp_flags.urg == 0 && packet.tcp_flags.ack == 0 && packet.tcp_flags.psh == 0 &&
				packet.tcp_flags.rst == 0 && packet.tcp_flags.syn == 0 && packet.tcp_flags.fin == 0) then
				#NULL
				$incident_number += 1
				print_alert("NULL scan", packet.ip_saddr, 'TCP', Base64.encode64(packet.payload))

			elsif (packet.tcp_flags.urg == 0 && packet.tcp_flags.ack == 0 && packet.tcp_flags.psh == 0 &&
				packet.tcp_flags.rst == 0 && packet.tcp_flags.syn == 0 && packet.tcp_flags.fin == 1) then
				#FIN
				$incident_number += 1
				print_alert("FIN scan", packet.ip_saddr, 'TCP', Base64.encode64(packet.payload))

			# elsif (!packet.tcp_flags.urg && packet.tcp_flags.ack && !packet.tcp_flags.psh && !packet.tcp_flags.rst && !packet.tcp_flags.syn && packet.tcp_flags.fin) then
			# 	#Maimon (FIN + ACK)
			# 	$incident_number += 1
			# 	print_alert("FIN/ACK scan", packet.ip_saddr, 'TCP', Base64.encode64(packet.payload))

			# elsif (!packet.tcp_flags.urg && packet.tcp_flags.ack && !packet.tcp_flags.psh && !packet.tcp_flags.rst && !packet.tcp_flags.syn && !packet.tcp_flags.fin) then
			# 	#ACK
			# 	$incident_number += 1
			# 	print_alert("ACK scan", packet.ip_saddr, 'TCP', Base64.encode64(packet.payload))

			elsif (packet.payload =~ /Nmap|nmap|NMAP/) then
				$incident_number += 1
				print_alert("Other Nmap scan", packet.ip_saddr, 'TCP', Base64.encode64(packet.payload))

			elsif (packet.payload =~ /nikto|Nikto/) then
				$incident_number += 1
				print_alert("Nikto scan", packet.ip_saddr, 'TCP', Base64.encode64(packet.payload))	
			end
		#Look for non-TCP nmap and nikto scans, assume they're UDP
		elsif (packet.payload =~ /Nmap|nmap|NMAP/) then
			$incident_number += 1
			print_alert("Other Nmap scan", packet.ip_saddr, 'UDP', Base64.encode64(packet.payload))
		elsif (packet.payload =~ /nikto|Nikto/) then
			$incident_number += 1
			print_alert("Nikto scan", packet.ip_saddr, 'UDP', Base64.encode64(packet.payload))	
		end

		#Look for credit cards in the clear
		# The following regex matches:
		# 4XXX-XXXX-XXXX-XXXX
		# 5XXX-XXXX-XXXX-XXXX
		# 6011-XXXX-XXXX-XXXX
		# 3XXX-XXXXXX-XXXXX
		# as well as accounting for variations in using dashes vs. no dashes vs. spaces
		# Source: http://www.sans.org/security-resources/idfaq/snort-detect-credit-card-numbers.php
		if (packet.payload =~ /(((4|5)\d{3}|6011)(-|\s)?\d{4}(-|\s)?\d{4}(-|\s)?\d{4}|3\d{3}(-|\s)?\d{6}(-|\s)?\d{5})/) then
			$incident_number += 1
			print_alert("Credit card leaked in the clear", packet.ip_saddr, 'HTTP', Base64.encode64(packet.payload))
		end
	end
end

def analyze_log(log)
    file = File.open(log, 'r')
    file.each_line do |line|
    	payload = line.split('"')[1]
    	ip_saddr = line.split(' ')[0]
        if (line =~ /Nmap|nmap|NMAP/) then
        	$incident_number += 1
        	print_alert("Nmap scan", ip_saddr, 'HTTP', payload)
        elsif (line =~ /Nikto|nikto/) then
        	$incident_number += 1
        	print_alert("Nikto scan", ip_saddr, 'HTTP', payload)
        elsif (line =~ /masscan|Masscan/) then
        	$incident_number += 1
        	print_alert("Masscan", ip_saddr, 'HTTP', payload)
        elsif (line =~ /phpMyAdmin/) then
        	$incident_number += 1
        	print_alert("Someone looking for phpMyAdmin stuff", ip_saddr, 'HTTP', payload)
        elsif (line =~ /\(\) ?\{ ?:; ?\}/) then
        	$incident_number += 1
        	print_alert("Shellshock scan", ip_saddr, 'HTTP', payload)
        elsif (line =~ /(\\x[0-9a-f]{2})/i) then
        	$incident_number += 1
        	print_alert("Shellcode", ip_saddr, 'HTTP', payload)
        end
    end
    file.close
end


def print_alert(incident, source_IP, protocol, payload)
	puts '%d. ALERT: %s is detected from %s (%s) (%s)!' %[$incident_number, incident, source_IP, protocol, payload]
end

def main()
	if ARGV[0] == nil
	    monitor_stream()
	elsif ARGV[1] != nil && ARGV[0] == '-r'
	    analyze_log(ARGV[1])
	else
	    puts "Usage: ruby alarm.rb [-r <web_server_log>]"
	end
end

main()
