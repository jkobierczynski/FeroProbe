//! Host groups, as nmap scans in them: hosts are pinged in batches of up to
//! [`PING_GROUP`] and then port-scanned and reported a group at a time, so
//! results (and the report files) arrive as the scan goes, which is what
//! lets `--resume` carry on after an abort.

/// How many targets host discovery takes at once (nmap's `PING_GROUP_SZ`),
/// or `--min-hostgroup` when that is larger.
pub const PING_GROUP: usize = 4096;

/// nmap's defaults for `--min-hostgroup` and `--max-hostgroup`.
pub const DEFAULT_MIN: usize = 1;
pub const DEFAULT_MAX: usize = 100_000;

/// The scans a run does, as far as the group size depends on them.
pub struct GroupFacts {
    /// TCP ports per host, if a TCP scan runs.
    pub tcp_ports: Option<usize>,
    pub udp: bool,
    pub sctp: bool,
    /// The `-T` level, 0-5.
    pub timing_level: u8,
    pub min: usize,
    pub max: usize,
}

/// How many hosts the next group scans, given how many targets are already
/// done: nmap's `determineScanGroupSize`. 128 for UDP or SCTP scans, for
/// TCP 1024 divided by the port count but at least 64, and 16 otherwise.
/// A TCP scan of more than 1000 ports at `-T4` or slower starts with a
/// quick group of 4 (8 at `-T4`) to show results early, and takes those
/// hosts off the second group so later groups stay aligned on network
/// boundaries such as a /24. Then held between `--min-hostgroup` and
/// `--max-hostgroup`.
pub fn scan_group_size(done: usize, f: &GroupFacts) -> usize {
    let mut size = 16;
    if f.udp || f.sctp {
        size = 128;
    } else if let Some(ports) = f.tcp_ports {
        size = (1024 / ports.max(1)).max(64);
        if ports > 1000 && f.timing_level <= 4 {
            let quick = if f.timing_level == 4 { 8 } else { 4 };
            if done == 0 {
                size = quick;
            } else if done == quick && size > quick * 2 {
                size -= quick;
            }
        }
    }
    // nmap's box(): the minimum wins when the two cross.
    size.min(f.max).max(f.min).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(tcp: Option<usize>, udp: bool, level: u8) -> GroupFacts {
        GroupFacts {
            tcp_ports: tcp,
            udp,
            sctp: false,
            timing_level: level,
            min: DEFAULT_MIN,
            max: DEFAULT_MAX,
        }
    }

    #[test]
    fn nmaps_group_sizes() {
        // Ping scans and -sO.
        assert_eq!(scan_group_size(0, &facts(None, false, 3)), 16);
        assert_eq!(scan_group_size(0, &facts(Some(1000), true, 3)), 128);
        // The default 1000 ports: 1024/1000 is 1, so 64.
        assert_eq!(scan_group_size(0, &facts(Some(1000), false, 3)), 64);
        assert_eq!(scan_group_size(0, &facts(Some(4), false, 3)), 256);
        // -p- starts with a quick group, then takes it off the next one.
        let all = facts(Some(65535), false, 3);
        assert_eq!(scan_group_size(0, &all), 4);
        assert_eq!(scan_group_size(4, &all), 60);
        assert_eq!(scan_group_size(64, &all), 64);
        let t4 = facts(Some(65535), false, 4);
        assert_eq!(scan_group_size(0, &t4), 8);
        assert_eq!(scan_group_size(8, &t4), 56);
        assert_eq!(scan_group_size(0, &facts(Some(65535), false, 5)), 64);
    }

    #[test]
    fn min_and_max_hostgroup() {
        let mut f = facts(Some(1000), false, 3);
        f.max = 10;
        assert_eq!(scan_group_size(0, &f), 10);
        f.min = 20;
        assert_eq!(scan_group_size(0, &f), 20);
    }
}
