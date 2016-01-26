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
        This SharePwn module finds potential SharePoint resources via brute force
        browsing.
      },
      'Author' 		=> 'J Parsons "0rigen"',
      'License'		=> MSF_LICENSE))

    register_options(
      [
        OptString.new('PATH', [ true,  "The target's SharePoint path", '/']),
        OptString.new('ErrorCode', [ false, 'ErrorCode for non-existent resources (usually 404)', '404']),
        OptPath.new('DICTIONARY',   [ false, "Path of SP resource dictionary",
            File.join(Msf::Config.data_directory, "sharepwn", "brute_list.txt")
          ]
        )

      ], self.class)

  end

  def run_host(ip)
    conn = true
    ecode = nil
    emesg = nil

    #DEBUG
    print("#{ip}")

    tpath = normalize_uri(datastore['PATH'])
    if tpath[-1,1] != '/'
      tpath += '/'
    end

    # DEBUG
    #print_status("Constructed " + tpath)

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

          #DEBUG
          #print_status("Requesting " + (tpath + testfdir))

          res = send_request_cgi({
            'uri'  		=>  tpath+testfdir,
            'method'   	=> 'GET',
            'ctype'		=> 'text/html'
          }, 20)

          #DEBUG
          #print_status("#{res.code}")

          if(res.code.to_i == 302)
          	print_status("Redirected #{wmap_base_url}#{tpath}#{testfdir} #{res.code} (#{wmap_target_host})")
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
            if(res.code.to_i != 302) and (res.code.to_i != ecode)
            	print_status("Found #{wmap_base_url}#{tpath}#{testfdir} #{res.code} (#{wmap_target_host})")
            end

            if res.code.to_i == 401 or res.code.to_i == 403
              print_status("#{wmap_base_url}#{tpath}#{testfdir} requires authentication: #{res.headers['WWW-Authenticate']}")

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
