//! The `-h`/`--help` page, laid out like nmap's: one line per option,
//! grouped under the same section headings, in our own words.

pub(crate) const HELP: &str = concat!(
    "FeroProbe ",
    env!("CARGO_PKG_VERSION"),
    " ( https://github.com/jkobierczynski/FeroProbe )
Usage: feroprobe [Scan Type(s)] [Options] {target specification}
TARGET SPECIFICATION:
  Hostnames, IP addresses, CIDR blocks and ranges, IPv4 or IPv6.
  Ex: scanme.example.org, 192.168.0.0/24, 10.0.0.1-20, fe80::1%eth0
  -iL <inputfilename>: Read targets from a file (\"-\" for standard input)
  --exclude <host1[,host2][,host3],...>: Leave out these hosts/networks
  --excludefile <exclude_file>: Leave out the hosts listed in a file
HOST DISCOVERY:
  -sn: Ping scan - find the hosts that are up, no port scan
  -Pn: Skip host discovery - treat every target as up
  -PS/PA/PU[portlist]: TCP SYN/connect, TCP ACK or UDP probes to these ports
  -PE/PP/PM: ICMP echo, timestamp and address mask request probes
  -n/-R: Never resolve names / resolve every target [default: hosts that are up]
  --dns-servers <serv1[,serv2],...>: Ask these servers for reverse DNS
  --disable-arp-ping, --send-ip: No ARP or neighbour discovery on the local link
  --randomize-hosts: Scan the targets in random order
  --traceroute: Trace the hop path to each host
SCAN TECHNIQUES:
  -sS/sT/sA/sW/sM: TCP SYN/connect/ACK/Window/Maimon scans
  -sU: UDP scan
  -sN/sF/sX: TCP NULL, FIN and Xmas scans
  --scanflags <flags>: Send these TCP flags (e.g. SYNFIN) instead
PORT SPECIFICATION AND SCAN ORDER:
  -p, --ports <port ranges>: Scan only these ports
    Ex: -p 443; -p 1-1024; -p 22,80,T:8080,U:53,123
  --exclude-ports <port ranges>: Leave these ports out (from -P probes too)
  -F: Fast mode - the 100 most common ports
  -r: Scan ports in order instead of shuffled
  --top-ports <number>: Scan the <number> most common ports
SERVICE/VERSION DETECTION:
  -sV: Ask open ports which service and version they run
  --version-timeout <ms>: How long to wait for each service reply
OS DETECTION:
  -O: Guess the operating system
TIMING AND PERFORMANCE:
  A <time> is in seconds unless it ends in ms, s, m or h (e.g. 500ms, 30m).
  -T<0-5>: Timing template, from paranoid (0) to insane (5)
  --timeout <ms>: How long to wait for an answer to each probe
  --retries <tries>: Extra attempts for probes without an answer
  -c, --concurrency <number>: Connect/UDP probes in flight at once
  --min-rate <number>: Send at least <number> packets per second
  --max-rate <number>: Send at most <number> packets per second
  --scan-delay <time>: Wait at least <time> between probes
  --host-timeout <time>: Give up on a host after <time>
OUTPUT:
  -oN/-oX/-oG/-oJ <file>: Write normal, XML, grepable or JSON output to <file>
  -oA <basename>: Write normal, XML and grepable output at once
  -o, --output <table|json|xml|grepable>: Format on standard output
  -v: More progress output (-vv for even more)
  --reason: Show why each port got its state
  --open: Show only open (or possibly open) ports
  --stats-every <time>: Print a progress line every <time>
  --nmap-label: Write scanner=\"nmap\" in XML, for tools that need it
MISC:
  -6: Scan the IPv6 address of hostnames
  -A: Version and OS detection plus traceroute
  --oui-file <file>: IEEE OUI list for MAC vendor names
  -V, --version: Print the version
  -h, --help: Print this help page
EXAMPLES:
  feroprobe -v -A scanme.example.org
  feroprobe -v -sn 192.168.0.0/16 10.0.0.0/8
  feroprobe -Pn -p 80 -oX scan.xml 10.0.0.1-50
SEE THE README (https://github.com/jkobierczynski/FeroProbe) FOR MORE OPTIONS AND EXAMPLES
"
);

#[cfg(test)]
mod tests {
    use super::HELP;
    use clap::CommandFactory;

    #[test]
    fn every_option_is_listed() {
        let cmd = crate::Args::command();
        for arg in cmd.get_arguments() {
            if arg.is_positional() {
                continue;
            }
            // Spelled the way users type them: nmap's two-letter flags for
            // the rewritten long options.
            let shown = match arg.get_long() {
                Some("input-file") => "-iL".to_string(),
                Some("output-normal" | "output-xml" | "output-grepable" | "output-json") => {
                    "-oN/-oX/-oG/-oJ".to_string()
                }
                Some("output-all") => "-oA".to_string(),
                Some(long) => format!("--{long}"),
                None => format!("-{}", arg.get_short().unwrap()),
            };
            let found = match shown.as_str() {
                // -s and -P take the type run on, listed as -sS, -PS ...
                "-s" => HELP.contains("-sS"),
                "-P" => HELP.contains("-Pn"),
                "-T" => HELP.contains("-T<0-5>"),
                _ => {
                    HELP.contains(&format!("{shown}:"))
                        || HELP.contains(&format!("{shown} "))
                        || HELP.contains(&format!("{shown},"))
                        || HELP.contains(&format!("{shown}/"))
                }
            };
            assert!(found, "{shown} is missing from the help page");
        }
    }

    #[test]
    fn lines_fit_a_terminal() {
        for line in HELP.lines() {
            assert!(line.chars().count() <= 90, "too long: {line}");
        }
    }
}
