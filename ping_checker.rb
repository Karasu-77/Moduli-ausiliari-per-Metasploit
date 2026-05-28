require 'msf/core' #libreria per metasploit

class MetasploitModule < Msf::Auxiliary #crea una nuova classe con le caratteristiche di un modulo ausiliario
  include Msf::Auxiliary::Scanner #per prendere input
  include Msf::Auxiliary::Report #per salvare nel database


  def initialize(info = {}) #inizializza e richiama la classe "default" sopra 
    super(update_info(info,
      'Name'        => 'Ping Host Checker',
      'Description' => 'Checks if hosts are reachable via ICMP ping',
      'Author'      => ['Your Name'],
      'License'     => MSF_LICENSE
    ))

    register_options([
      OptInt.new('COUNT', [false, 'Numero di pacchetti da inviare', 2]),
      OptInt.new('TIMEOUT', [false, 'Latenza ping in secondi', 3])
    ])
  end

  def ping_host(ip) #metodo che prende in input il ping
    count   = datastore['COUNT']
    timeout = datastore['TIMEOUT']
  
    #runna il comando e poi vede il match per Windows o Linux/MacOS
    cmd = if RUBY_PLATFORM =~ /mingw|mswin/ #per verificare il SO utilizzato
            "ping -n #{count} -w #{timeout * 1000} #{ip}"
          else
            "ping -c #{count} -W #{timeout} #{ip}"
          end
  
    output = `#{cmd} 2>&1`
    success = $?.exitstatus == 0
  
    #stessa cosa di sopra ma per visualizzare la latenza
    latency = output.match(/[Tt]ime[=<]([\d.]+)\s*ms/)&.captures&.first
    latency ||= output.match(/Average\s*=\s*([\d.]+)\s*ms/)&.captures&.first
    latency ||= output.match(/min\/avg\/max[^=]+=\s*[\d.]+\/([\d.]+)/)&.captures&.first
  
    { reachable: success, latency: latency, raw: output }
  end

  def run_host(ip)
    result = ping_host(ip)

    if result[:reachable] #se il ping ha successo
      latency_str = result[:latency] ? " (#{result[:latency]}ms)" : ""
      print_good("#{ip} Risponde#{latency_str}")

      #verifica che l'host pingato sia vivo
      report_host(
        host:   ip,
        state:  Msf::HostState::Alive,
        info:   "Risposta ICMP latenza del ping#{latency_str}"
      )

      #per salvare nel database
      report_note(
        host:  ip,
        type:  'host.ping',
        data:  { latency_ms: result[:latency], reachable: true }
      )
    else
      print_status("#{ip} è down o blocca una comunicazione ICMP") #se l'host non risponde

      report_host(
        host:  ip,
        state: Msf::HostState::Unknown
      )
    end
  end
end