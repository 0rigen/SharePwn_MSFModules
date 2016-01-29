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
      'Name'   		=> 'SharePwn:VersionID - SharePoint & Server Version Identifier',
      'Description'	=> %q{
        This SharePwn module performs an initial interrogation of a SharePoint server to discover
        the installed SharePoint version, as well as the current Health Score and other server information.
      },
      'Author' 		=> 'J Parsons "0rigen" <0rigen [at] 0rigen.net>',
      'License'		=> MSF_LICENSE))

    register_options(
      [
        OptString.new('PATH', [ false,  "The target's SharePoint path, if not at webroot", ''])
      ], self.class)

    deregister_options('THREADS')
  end


  def run_host(ip)
    tpath = normalize_uri(datastore['PATH'])

    if (tpath[-1,1] != '/')
      tpath += '/'
    end

    prot  = datastore['SSL'] ? 'https' : 'http'

    connect

    # Timeout = 3, Redirect depth = 2
    res = send_request_cgi!({
      'uri'  		=>  tpath,
      'method'   	=> 'GET'#,
      #'ctype'		=> 'text/html'
    }, 20, 2)

    disconnect

    # Fail gracefully is the request fails
    return if not res

    # Try to read the SP header
    if (res.headers['microsoftsharepointteamservices'])
      case res.headers['microsoftsharepointteamservices']
      when res.headers['microsoftsharepointteamservices'].starts_with?('6')
        print_status("SharePoint Version: " + res.headers['microsoftsharepointteamservices'] + " SP 2003 ")
      when res.headers['microsoftsharepointteamservices'].starts_with?('12')
        print_status("SharePoint Version: " + res.headers['microsoftsharepointteamservices'] + " SP 2007 ")
      when res.headers['microsoftsharepointteamservices'].starts_with?('14')
        print_status("SharePoint Version: " + res.headers['microsoftsharepointteamservices'] + " SP 2010 ")
      when res.headers['microsoftsharepointteamservices'].starts_with?('15')
        print_status("SharePoint Version: " + res.headers['microsoftsharepointteamservices'] + " SP 2013 ")
      else
        print_status("Unrecognized SharePoint Version: " + res.headers['microsoftsharepointteamservices'])
      end
    end

    if (res.headers['x-sharepointhealthscore'])
      print_status("SharePoint Health Score: " + res.headers['x-sharepointhealthscore'])
    end
    if (res.headers['x-aspnet-version'])
      print_status("ASP.NET Version: " + res.headers['x-aspnet-version'])
    end
    if (res.headers['server'])
      print_status("Server Version: " + res.headers['server'])
    end
  end
end