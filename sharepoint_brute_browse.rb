##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
#  This module is largely based on the dir_scanner.rb module
#

require 'rex/proto/http'
require 'msf/core'
require 'thread'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanDir
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'   		=> 'SharePwn:BruteBrowse - SharePoint Resource Locator',
      'Description'	=> %q{
        This SharePwn module searches for common SharePoint services, directories, and files via brute force
        browsing.  This information can be used to test misconfigured permissions on SharePoint sites.
        To set an HTTP Error Code other than '404', use the Advanced Option 'ErrorCode'.
      },
      'Author' 		=> 'J Parsons "0rigen" <0rigen [at] 0rigen.net>',
      'License'		=> MSF_LICENSE))

    register_options(
      [
        OptString.new('PATH', [ false,  "The target's SharePoint path, if not at webroot", '']),
        OptPath.new('DICTIONARY',   [ false, "Path of SP resource dictionary",
            File.join(Msf::Config.data_directory, "sharepwn", "browse_list.txt")
          ]
        )

      ], self.class)

    register_advanced_options(
      [
        OptString.new('ErrorCode', [ false, 'ErrorCode for non-existent resources (usually 404)', '404'])
      ], self.class)

  end

  def run_host(ip)
    conn = true
    ecode = nil
    emesg = nil

    tpath = normalize_uri(datastore['PATH'])

    if (tpath[-1,1] != '/')
      tpath += '/'
    end

    # If it's just the root path, then don't bother with thism, otherwise we'll double up slashes
    if(tpath == '/')
      tpath = ""
    end


    if datastore['ErrorCode']
    	ecode = datastore['ErrorCode'].to_i
    	print_line("Using Error Code #{ecode}")
    else
    	ecode == 404
    	print_line("Using Error Code 404")
    end

    vhost = datastore['VHOST'] || wmap_target_host
    prot  = datastore['SSL'] ? 'https' : 'http'

    return if not conn

    nt = datastore['TestThreads'].to_i
    nt = 1 if nt == 0

    dm = datastore['NoDetailMessages']

    queue = []
    File.open(datastore['DICTIONARY'], 'rb').each_line do |testd|
      queue << testd.strip
    end

    while(not queue.empty?)
      t = []
      1.upto(nt) do
        t << framework.threads.spawn("Module(#{self.refname})-#{rhost}", false, queue.shift) do |testf|
          Thread.current.kill if not testf

          testfdir = testf

          # Timeout = 3, Redirect depth = 2
          res = send_request_cgi!({
            'uri'  		=>  tpath + testfdir,
            'method'   	=> 'GET',
            'ctype'		=> 'text/html'
          }, 20, 2)

          return if not res

          if res.body.include? "error" # SP usually just uses error.aspx rather than a 404
            next
          else
            begin
            # Status was redirected
            if(res.code.to_i == 302)
            	print_status("Redirected #{wmap_base_url}#{tpath}#{testfdir} <Response:#{res.code}>")
            end
            # Status is not redirect or not found
            if(res.code.to_i != 302) and (res.code.to_i != ecode) 
                print_status("Found #{wmap_base_url}#{tpath}#{testfdir} <Response:#{res.code}>")
            end

            if (res.code.to_i == 401) or (res.code.to_i == 403) or res.target_uri.include? "error"
                print_status("#{wmap_base_url}#{tpath}#{testfdir} requires authentication: #{res.headers['WWW-Authenticate']}")
            end
          end

            report_web_vuln(
              :host	=> ip,
              :port	=> rport,
              :vhost  => vhost,
              :ssl    => ssl,
              :path	=> "#{tpath}#{testfdir}",
              :method => 'GET',
              :pname  => "",
              :proof  => "Res code: #{res.code.to_s}",
              :risk   => 0,
              :confidence   => 100,
              :category     => 'directory',
              :description  => 'Directoy found.',
              :name   => 'directory'
            )
        
              report_note(
                :host	=> ip,
                :port	=> rport,
                :proto => 'tcp',
                :sname	=> (ssl ? 'https' : 'http'),
                :type	=> 'WWW_AUTHENTICATE',
                :data	=> "#{tpath}#{testfdir} Auth: #{res.headers['WWW-Authenticate']}",
                :update => :unique_data
              )

            end
          end

        end
      end
      t.map{|x| x.join }
    end
end