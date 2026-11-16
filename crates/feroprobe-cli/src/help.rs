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
  -sL: List Scan - simply list the targets (with reverse DNS), send nothing
  -sn: Ping scan - find the hosts that are up, no port scan
  -Pn: Skip host discovery - treat every target as up
  -PS/PA/PU/PY[portlist]: TCP SYN/connect, TCP ACK, UDP or SCTP INIT probes
  -PE/PP/PM: ICMP echo, timestamp and address mask request probes
  -PO[protocol list]: IP protocol ping (default ICMP, IGMP, IP-in-IP)
  -PR: Accepted for nmap compatibility; ARP is always used where it can be
  -n/-R: Never resolve names / resolve every target [default: hosts that are up]
  --dns-servers <serv1[,serv2],...>: Ask these servers for reverse DNS
  --system-dns: Use the system resolver (the default; overrides --dns-servers)
  --disable-arp-ping, --send-ip: No ARP or neighbour discovery on the local link
  --randomize-hosts: Scan the targets in random order
  --traceroute: Trace the hop path to each host
SCAN TECHNIQUES:
  -sS/sT/sA/sW/sM: TCP SYN/connect/ACK/Window/Maimon scans
  -sU: UDP scan
  -sN/sF/sX: TCP NULL, FIN and Xmas scans
  -sY/sZ: SCTP INIT and COOKIE ECHO scans
  -sO: IP protocol scan - which protocols (TCP, UDP, ICMP, ...) a host runs
  --scanflags <flags>: Send these TCP flags (e.g. SYNFIN) instead
  -b <FTP relay host>: FTP bounce scan ([user[:pass]@]server[:port])
FIREWALL/IDS EVASION AND SPOOFING:
  -e <iface>: Send and receive on this network interface
  -g, --source-port <portnum>: Send raw and UDP probes from this source port
  The next four: raw IPv4 TCP scans; private ranges, or public with opt-in:
  -f, --mtu <n>: Fragment raw IPv4 probes (8-byte pieces, or <n> per fragment)
  -D, --decoys <a,b,ME,c>: Cloak the scan among decoy source addresses
  -S, --source <addr>: Spoof the source address of raw IPv4 probes
  --allow-public-evasion: Authorize the above against public targets you may test
  --data <hex string>: Add these bytes to raw probes (ex: 0xdeadbeef)
  --data-string <string>: Add this text to raw probes
  --data-length <num>: Add <num> random bytes to raw probes
  --ip-options <options>: Send IPv4 probes with these IP options (R, T, U, L/S <hops>)
  --ttl <val>: Set the IP time-to-live (IPv6 hop limit) of probes
  --badsum: Send probes with a wrong TCP/UDP/SCTP/ICMP checksum
PORT SPECIFICATION AND SCAN ORDER:
  -p, --ports <port ranges>: Scan only these ports
    Ex: -p 443; -p 1-1024; -p 22,80,T:8080,U:53,S:2905; -sO -p P:1,6,17
  --exclude-ports <port ranges>: Leave these ports out (from -P probes too)
  -F: Fast mode - the 100 most common ports
  -r: Scan ports in order instead of shuffled
  --top-ports <number>: Scan the <number> most common ports
SERVICE/VERSION DETECTION:
  -sV: Ask open ports which service and version they run
  --version-timeout <ms>: How long to wait for each service reply
  --version-intensity <0-9>: How many probes to try (default 7; 9 tries all)
  --version-light: Only the most likely probes (intensity 2)
  --version-all: Every probe (intensity 9)
  --version-trace: Print each service probe, reply and matching rule
  --service-rules <file>: Use these probes and rules instead of the built-in ones
OS DETECTION:
  -O: Enable OS detection
  --osscan-limit: Limit OS detection to promising targets
  --osscan-guess: Guess OS more aggressively
  --max-os-tries <tries>: OS detection tries per host (default 5)
TIMING AND PERFORMANCE:
  A <time> is in seconds unless it ends in ms, s, m or h (e.g. 500ms, 30m).
  -T<0-5>: Timing template, from paranoid (0) to insane (5)
  --initial-rtt-timeout <time>: How long a probe waits before any round trip
      is measured; after that, each host's wait follows its round-trip times
  --min-rtt-timeout, --max-rtt-timeout <time>: Limits on that adaptive wait
  --timeout <ms>: A fixed wait for each probe (sets all three of the above)
  --retries, --max-retries <tries>: Most resends of a probe without an answer
  -c, -M, --concurrency, --max-parallelism <number>: Most probes waiting at once
  --min-parallelism <number>: At least <number> probes allowed to wait at once
  --min-hostgroup/--max-hostgroup <size>: Parallel host scan group sizes
  --min-rate <number>: Send at least <number> packets per second
  --max-rate <number>: Send at most <number> packets per second
  --scan-delay <time>: Wait at least <time> between probes
  --max-scan-delay <time>: Longest delay the scan may add for a lossy host
  --host-timeout <time>: Give up on a host after <time>
  --defeat-rst-ratelimit: Don't slow a SYN scan down for rate-limited RSTs
OUTPUT:
  -oN/-oX/-oS/-oG/-oJ <file>: Write normal, XML, script kiddie, grepable
     or JSON output to <file>
  -oA <basename>: Write normal, XML and grepable output at once
  --append-output: Add to the output files instead of overwriting them
  --stylesheet <path/URL>: Link this XSL stylesheet from the XML output
  --webxml: Link the published FeroProbe stylesheet, for more portable XML
  --no-stylesheet: Link no XSL stylesheet from the XML output
  -o, --output <table|json|xml|grepable>: Format on standard output
  -v: More progress output (-vv for even more)
  -d, --debug: More debugging output (-dd or -d<level> for more)
  --reason: Show why each port got its state
  --packet-trace: Show every packet sent and received
  --explain: Before scanning, show the plan and the reason for each step
  --dry-run: Show every probe that would be sent, but send nothing
  --open: Show only open (or possibly open) ports
  --stats-every <time>: Print a progress line every <time>
  --nmap-label: Write scanner=\"nmap\" in XML, for tools that need it
  --iflist: Print host interfaces and routes (for debugging)
  --noninteractive: No keys during the scan (v/V, d/D, p/P, ?, status)
  --resume <filename>: Resume an aborted scan
MISC:
  -6: Scan the IPv6 address of hostnames
  -A: Version and OS detection plus traceroute
  --override-ics-protection: Allow -sV/-O/-A once despite ics_protection = true
  --oui-file <file>: IEEE OUI list for MAC vendor names
  --privileged: Assume raw sockets work
  --unprivileged: Act as an ordinary user, with no raw sockets
  -V, --version: Print the version
  -h, --help: Print this help page
EXAMPLES:
  feroprobe -v -A scanme.example.org
  feroprobe -v -sn 192.168.0.0/16 10.0.0.0/16
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
                Some(
                    "output-normal" | "output-xml" | "output-skid" | "output-grepable"
                    | "output-json",
                ) => "-oN/-oX/-oS/-oG/-oJ".to_string(),
                Some("output-all") => "-oA".to_string(),
                // nmap's single-letter names for the evasion options.
                Some("decoys") => "-D".to_string(),
                Some("source") => "-S".to_string(),
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

    /// The reference manual documents every option too, under its own
    /// heading, so a new option can't be left out of it.
    #[test]
    fn every_option_is_in_the_manual() {
        const MANUAL: &str = include_str!("../../../docs/manual.md");
        let headings: Vec<&str> = MANUAL
            .lines()
            .filter(|l| l.starts_with("#### ") || l.starts_with("### "))
            .collect();
        let cmd = crate::Args::command();
        for arg in cmd.get_arguments() {
            if arg.is_positional() {
                continue;
            }
            let shown = match arg.get_long() {
                Some("input-file") => "-iL".to_string(),
                Some("output-normal") => "-oN".to_string(),
                Some("output-xml") => "-oX".to_string(),
                Some("output-grepable") => "-oG".to_string(),
                Some("output-json") => "-oJ".to_string(),
                Some("output-all") => "-oA".to_string(),
                Some("output-skid") => "-oS".to_string(),
                Some(long) => format!("--{long}"),
                None => format!("-{}", arg.get_short().unwrap()),
            };
            let shown = match shown.as_str() {
                // -s and -P take the type run on; each type has a heading.
                "-s" => "-sS".to_string(),
                "-P" => "-Pn".to_string(),
                "-T" => "-T<0-5>".to_string(),
                _ => shown,
            };
            let found = headings.iter().any(|h| {
                h.contains(&format!("`{shown}`"))
                    || h.contains(&format!("`{shown} "))
                    || h.contains(&format!("`{shown}["))
                    || h.contains(&format!("({shown})"))
            });
            assert!(found, "{shown} has no heading in docs/manual.md");
        }
    }

    #[test]
    fn lines_fit_a_terminal() {
        for line in HELP.lines() {
            assert!(line.chars().count() <= 90, "too long: {line}");
        }
    }
}
