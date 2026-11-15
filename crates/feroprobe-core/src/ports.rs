//! Port specification parsing (nmap-style `-p` syntax).

use crate::Error;
use crate::model::Protocol;

/// FeroProbe's own ranked list of 1000 TCP ports, used when no ports are
/// specified (nmap's default is also its 1000 most common ports). It is not
/// nmap's list: nmap's port data is under its own licence, so this one is
/// built independently, in three tiers. Tier 1 is the hand-ranked list of
/// the most common services (-F scans its first 100). Tier 2 adds services
/// commonly exposed on networks today, grouped by kind. Tier 3 fills the
/// rest with the IANA-registered ports in ascending order, so the
/// well-known range is mostly covered.
#[rustfmt::skip]
pub const TOP_PORTS: &[u16] = &[
    // Tier 1: the most common services; -F takes the first 100.
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993,
    5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026,
    2000, 8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646,
    5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990,
    5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190,
    3000, 5432, 1900, 3986, 13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100,
    119, 37, 6379, 27017, 9200, 11211, 5672, 1883, 8883, 2375, 6443, 9090, 9443, 5985, 5986,
    161, 162, 69, 123,
    // Tier 2: remote access and administration.
    2222, 5901, 5902, 5903, 5938, 3260, 8291, 8728, 8729, 10050, 10051, 4786, 7547, 2869, 5431,
    49000, 37215, 52869, 1080, 3129, 8118, 9050, 9051, 5500, 5801, 5904, 5910, 5911, 6129, 512,
    2200, 47001, 1194, 4444, 12345, 31337,
    // Tier 2: web and application servers.
    8001, 8082, 8083, 8084, 8085, 8088, 8089, 8090, 8091, 8181, 8880, 9000, 9001, 7001, 7002,
    4443, 5001, 3001, 591, 593, 808, 888, 2082, 2083, 2086, 2087, 2095, 2096, 4000, 4001, 4567,
    4848, 5080, 5443, 6080, 7000, 7080, 7443, 7777, 8002, 8010, 8020, 8060, 8069, 8086, 8087,
    8099, 8100, 8123, 8180, 8200, 8222, 8280, 8281, 8333, 8400, 8444, 8500, 8530, 8531, 8600,
    8800, 8834, 8881, 8899, 8983, 9002, 9009, 9043, 9060, 9080, 9081, 9091, 9180, 9191, 9292,
    9500, 9800, 9876, 9898, 9980, 9981, 10001, 10080, 10443, 16080, 18080, 28017, 50000, 50070,
    50075, 60000, 82, 83, 84, 85, 3333, 2080, 8139, 8161, 8042, 8545,
    // Tier 2: databases.
    1521, 1522, 1526, 1527, 1830, 2483, 2484, 3050, 3351, 5433, 5984, 6380, 7199, 7474, 7687,
    8529, 9042, 9160, 26257, 27018, 27019, 28015, 33060, 1583, 2638,
    // Tier 2: messaging and queues.
    4369, 5671, 15672, 25672, 61613, 61614, 61616, 9092, 2181, 2888, 3888, 4222, 6222, 6667,
    6697, 5222, 5223, 5269,
    // Tier 2: containers, orchestration and monitoring.
    2376, 2377, 2379, 2380, 4243, 6783, 10250, 10255, 10256, 10257, 10259, 30000, 9093, 9094,
    9095, 9300, 5601, 8300, 8301, 8302, 4646, 4647, 4648, 50051, 6060, 7946,
    // Tier 2: files, storage and version control.
    20, 3690, 9418, 4045, 6346, 6881, 6882, 6883, 6889, 6969, 8384, 22000, 115,
    // Tier 2: mail.
    109, 563, 2525, 4190, 7071, 366,
    // Tier 2: directory and authentication.
    636, 3268, 3269, 464, 749, 750, 49,
    // Tier 2: Windows.
    1801, 2103, 2105, 2107, 2179, 5722, 9389, 49158, 49159, 49160, 49161, 49163, 49165, 49167,
    49175, 49176,
    // Tier 2: printing and scanning.
    9101, 9102, 9103, 9220, 6566,
    // Tier 2: voice, video and media.
    5061, 8554, 1935, 32400, 8096, 3689, 7100, 62078, 55443,
    // Tier 2: industrial.
    102, 502, 2404, 20000, 44818, 1911, 4911, 9600, 18245, 18246, 1962, 5007, 789, 2455,
    // Tier 2: games.
    25565, 27015,
    // Tier 3: the remaining IANA-registered TCP ports, ascending.
    1, 2, 3, 5, 11, 17, 18, 19, 27, 29, 31, 33, 38, 39, 41, 42, 43, 44, 45, 46, 48, 50, 52, 54,
    55, 56, 58, 62, 63, 64, 65, 66, 67, 68, 70, 71, 72, 73, 74, 76, 78, 86, 89, 90, 91, 92, 93,
    94, 95, 96, 97, 98, 99, 101, 103, 104, 105, 107, 108, 112, 116, 117, 118, 120, 121, 122,
    124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 136, 137, 138, 140, 141, 142, 145,
    146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 163, 164, 165,
    166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 180, 181, 182, 183, 184,
    185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 200, 201, 202, 203,
    204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221,
    222, 223, 224, 242, 243, 244, 245, 246, 247, 248, 256, 257, 259, 260, 261, 262, 263, 264,
    265, 266, 267, 268, 269, 271, 280, 281, 282, 283, 284, 286, 287, 308, 309, 310, 311, 312,
    313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 333, 344, 345, 346, 347, 348,
    349, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 360, 361, 362, 363, 364, 365, 367,
    368, 369, 370, 371, 372, 373, 374, 375, 376, 377, 378, 379, 380, 381, 382, 383, 384, 385,
    386, 387, 388, 390, 391, 392, 393, 394, 395, 396, 397, 398, 399, 400, 401, 402, 403, 404,
    405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 419, 420, 421, 422,
    423, 424, 425, 426, 428, 429, 430, 431, 432, 433, 434, 435, 436, 437, 438, 439, 440, 441,
    442, 446, 447, 448, 449, 450, 451, 452, 453, 454, 455, 456, 457, 458, 459, 460, 461, 462,
    463, 466, 467, 468, 469, 470, 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481, 482,
    483, 484, 485, 486, 487, 488, 489, 490, 491, 492, 493, 494, 495, 496, 497, 498, 499, 500,
    501, 503, 504, 505, 506, 507, 508, 509, 510, 511, 516, 517, 518, 519, 520, 521, 522, 523,
    524, 525, 526, 527, 528, 529, 530, 531, 532, 533, 534, 535, 536, 537, 538, 539, 540, 541,
    542, 545, 546, 547, 549, 550, 551, 552, 553, 555, 556, 557, 558, 559, 560, 561, 562, 564,
    565, 566, 567, 568, 569, 570, 571, 572, 573, 574, 575, 576, 577, 578, 579, 580, 581, 582,
    583, 584, 586, 588, 589, 590, 592, 594, 595, 596, 597, 598, 599, 600, 601, 602, 603, 604,
    605, 606, 607, 608, 609, 610, 611, 612, 613, 614, 615, 616, 617, 618, 619, 620, 621, 622,
    623, 624, 625, 626, 627, 628, 629, 630, 632, 633, 634, 635, 637, 638, 639, 640, 641, 642,
    643, 644, 645, 647, 648, 649, 650, 651, 652, 653, 654, 655, 656, 657, 658, 660, 661, 662,
    663, 664, 665, 666, 667, 668, 669, 670, 671, 672, 673, 674, 675, 676, 677, 678, 679, 680,
    681, 682, 683, 684, 685, 686, 687, 688, 689, 690, 691, 692, 693, 694, 695, 696, 697, 698,
    699, 700, 701, 702, 704, 705, 706, 707, 709, 710, 711, 712, 713, 714, 715, 729, 730, 731,
    741, 742, 744, 747, 748, 751, 752, 753, 754, 758, 759, 760, 761, 762, 763, 764, 765, 767,
    769, 770, 771, 772, 773, 774, 775, 776, 777, 780, 800, 801, 802, 810, 828, 829, 830, 831,
    832, 833, 847, 848, 853, 854, 860, 861, 862, 886, 887, 900, 901, 902, 903, 910,
];

/// FeroProbe's own ranked list of 1000 UDP ports, built like [`TOP_PORTS`].
/// Tier 1 is ordered by how often the service is found answering: network
/// infrastructure first (DNS, NTP, SNMP, NetBIOS, DHCP, IKE, syslog, UPnP,
/// mDNS), then VPN, VoIP, management, industrial and game ports; -F scans
/// those 100. Tier 2 adds more discovery, VPN, media and game ports, and
/// tier 3 the IANA-registered UDP ports in ascending order.
#[rustfmt::skip]
pub const TOP_UDP_PORTS: &[u16] = &[
    // Tier 1: the most common services, the -F list.
    53, 123, 161, 137, 67, 68, 69, 500, 514, 520, 1900, 5353, 138, 139, 135, 445, 631, 1434,
    4500, 49152, 162, 111, 88, 389, 2049, 1812, 1813, 1645, 1646, 1701, 1194, 5060, 3478, 443,
    5355, 3702, 5683, 51820, 623, 546, 547, 427, 464, 177, 199, 521, 1719, 3283, 3389, 3544,
    4789, 5004, 5005, 5351, 5632, 7, 9, 13, 17, 19, 37, 49, 513, 517, 518, 1025, 1026, 1027,
    1028, 1029, 2123, 2152, 2427, 2727, 5000, 5093, 9600, 10000, 11211, 17185, 20000, 27015,
    30718, 33434, 44818, 47808, 49153, 49154, 49156, 32768, 32769, 32771, 1718, 1604, 2222,
    1985, 3784, 5684, 9987, 3074,
    // Tier 2: infrastructure and discovery.
    1022, 1023, 1030, 523, 593, 626, 646, 664, 1512, 2048, 2148, 3130, 3401, 3391, 5246, 5247,
    6343, 8125, 8472, 10001, 9993, 17500, 3671, 34962, 34963, 34964, 4665, 4672, 6481, 8611,
    8612, 9200, 42, 120, 497, 749, 750, 989, 996, 997, 998, 999, 1001,
    // Tier 2: VPN, VoIP and media.
    2746, 3479, 5061, 5050, 1234, 6001, 7000, 7001, 8000, 8001, 9000, 9001, 10080, 1720,
    // Tier 2: databases and applications.
    1433, 2302, 2223, 3456, 4000, 5001, 5002, 5498, 6346, 6347, 6881, 6969, 4045, 1214, 54321,
    31337, 12345,
    // Tier 2: games.
    19132, 26000, 27016, 27960, 64738, 7777, 28015,
    // Tier 3: the remaining IANA-registered UDP ports, ascending.
    1, 2, 3, 5, 11, 18, 20, 21, 22, 23, 25, 27, 29, 31, 33, 38, 39, 41, 43, 44, 45, 46, 48, 50,
    52, 54, 55, 56, 58, 62, 63, 64, 65, 66, 70, 71, 72, 73, 74, 76, 78, 79, 80, 82, 83, 84, 85,
    86, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 101, 102, 103, 104, 105, 106, 107, 108, 109,
    110, 112, 113, 115, 116, 117, 118, 119, 121, 122, 124, 125, 126, 127, 128, 129, 130, 131,
    132, 133, 134, 136, 140, 141, 142, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154,
    155, 156, 157, 158, 159, 160, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174,
    175, 176, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193,
    194, 195, 196, 197, 198, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212,
    213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 242, 243, 244, 245, 246, 247,
    248, 256, 257, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 280, 281, 282,
    283, 284, 286, 287, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321,
    322, 333, 344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359,
    360, 361, 362, 363, 364, 365, 366, 367, 368, 369, 370, 371, 372, 373, 374, 375, 376, 377,
    378, 379, 380, 381, 382, 383, 384, 385, 386, 387, 388, 390, 391, 392, 393, 394, 395, 396,
    397, 398, 399, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414,
    415, 416, 417, 418, 419, 420, 421, 422, 423, 424, 425, 426, 428, 429, 430, 431, 432, 433,
    434, 435, 436, 437, 438, 439, 440, 441, 442, 444, 446, 447, 448, 449, 450, 451, 452, 453,
    454, 455, 456, 457, 458, 459, 460, 461, 462, 463, 465, 466, 467, 468, 469, 470, 471, 472,
    473, 474, 475, 476, 477, 478, 479, 480, 481, 482, 483, 484, 485, 486, 487, 488, 489, 490,
    491, 492, 493, 494, 495, 496, 498, 499, 501, 502, 503, 504, 505, 506, 507, 508, 509, 510,
    511, 512, 515, 516, 519, 522, 524, 525, 526, 527, 528, 529, 530, 531, 532, 533, 534, 535,
    536, 537, 538, 539, 540, 541, 542, 543, 544, 545, 548, 549, 550, 551, 552, 553, 554, 555,
    556, 557, 558, 559, 560, 561, 562, 563, 564, 565, 566, 567, 568, 569, 570, 571, 572, 573,
    574, 575, 576, 577, 578, 579, 580, 581, 582, 583, 584, 586, 587, 588, 589, 590, 591, 592,
    594, 595, 596, 597, 598, 599, 600, 601, 602, 603, 604, 605, 606, 607, 608, 609, 610, 611,
    612, 613, 614, 615, 616, 617, 618, 619, 620, 621, 622, 624, 625, 627, 628, 629, 630, 632,
    633, 634, 635, 636, 637, 638, 639, 640, 641, 642, 643, 644, 645, 647, 648, 649, 650, 651,
    652, 653, 654, 655, 656, 657, 658, 660, 661, 662, 663, 665, 666, 667, 668, 669, 670, 671,
    672, 673, 674, 675, 676, 677, 678, 679, 680, 681, 682, 683, 684, 685, 686, 687, 688, 689,
    690, 691, 692, 693, 694, 695, 696, 697, 698, 699, 700, 701, 702, 704, 705, 706, 707, 709,
    710, 711, 712, 713, 714, 715, 716, 729, 730, 731, 741, 742, 744, 747, 748, 751, 752, 753,
    754, 758, 759, 760, 761, 762, 763, 764, 765, 767, 769, 770, 771, 772, 773, 774, 775, 776,
    777, 780, 800, 801, 802, 810, 828, 829, 830, 831, 832, 833, 847, 848, 853, 854, 860, 861,
    862, 873, 886, 887, 888, 900, 901, 902, 903, 910, 911, 912, 913, 990, 991, 992, 995, 1000,
    1010, 1021, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045,
    1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060,
    1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075,
    1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090,
    1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1101, 1102, 1103, 1104, 1105,
    1106, 1107, 1108, 1110, 1111, 1112, 1113, 1114, 1115, 1116, 1117, 1118, 1119, 1120, 1121,
    1122, 1123, 1124, 1125, 1126, 1127, 1128, 1129, 1130, 1131, 1132, 1133, 1134, 1135, 1136,
    1137, 1138, 1139, 1140, 1141, 1142, 1143, 1144, 1145, 1146, 1147, 1148, 1149, 1150, 1151,
    1152, 1153, 1154, 1155, 1156, 1157, 1158, 1159, 1160, 1161, 1162, 1163, 1164, 1165, 1166,
    1167, 1168, 1169, 1170, 1171, 1172, 1173, 1174, 1175, 1176, 1177, 1178, 1179, 1180, 1181,
    1182, 1183, 1184, 1185, 1186, 1187, 1188, 1189, 1190, 1191, 1192, 1193, 1195, 1196, 1197,
    1198, 1199, 1200, 1201, 1202, 1203, 1204, 1205, 1206, 1207, 1208, 1209, 1210, 1211, 1212,
    1213, 1215, 1216, 1217, 1218, 1219, 1220, 1221, 1222, 1223, 1224, 1225, 1226,
];

/// The service usually found on a port, for display when version
/// detection did not run or learned nothing. Purely a label from the port
/// number.
pub fn service_name(protocol: Protocol, port: u16) -> &'static str {
    match protocol {
        Protocol::Ip => return u8::try_from(port).map_or("unknown", ip_protocol_name),
        Protocol::Sctp => return sctp_service_name(port),
        Protocol::Tcp | Protocol::Udp => {}
    }
    match (protocol, port) {
        (Protocol::Tcp, 21) => "ftp",
        (Protocol::Tcp, 22) => "ssh",
        (Protocol::Tcp, 23) => "telnet",
        (Protocol::Tcp, 25) => "smtp",
        (_, 53) => "domain",
        (Protocol::Udp, 67) => "dhcps",
        (Protocol::Udp, 68) => "dhcpc",
        (Protocol::Udp, 69) => "tftp",
        (Protocol::Tcp, 80) => "http",
        (Protocol::Tcp, 110) => "pop3",
        (_, 111) => "rpcbind",
        (Protocol::Udp, 123) => "ntp",
        (Protocol::Tcp, 135) => "msrpc",
        (Protocol::Udp, 137) => "netbios-ns",
        (Protocol::Udp, 138) => "netbios-dgm",
        (Protocol::Tcp, 139) => "netbios-ssn",
        (Protocol::Tcp, 143) => "imap",
        (Protocol::Udp, 161) => "snmp",
        (Protocol::Udp, 162) => "snmptrap",
        (Protocol::Tcp, 389) => "ldap",
        (Protocol::Tcp, 443) => "https",
        (Protocol::Tcp, 445) => "microsoft-ds",
        (Protocol::Tcp, 465) => "smtps",
        (Protocol::Udp, 500) => "isakmp",
        (Protocol::Udp, 514) => "syslog",
        (Protocol::Tcp, 587) => "submission",
        (Protocol::Tcp, 993) => "imaps",
        (Protocol::Tcp, 995) => "pop3s",
        (Protocol::Tcp, 1433) => "ms-sql-s",
        (Protocol::Tcp, 1883) => "mqtt",
        (Protocol::Udp, 1900) => "upnp",
        (_, 2049) => "nfs",
        (Protocol::Tcp, 2375) => "docker",
        (Protocol::Tcp, 3306) => "mysql",
        (Protocol::Tcp, 3389) => "ms-wbt-server",
        (Protocol::Udp, 4500) => "nat-t-ike",
        (Protocol::Tcp, 5432) => "postgresql",
        (Protocol::Udp, 5353) => "mdns",
        (Protocol::Tcp, 5672) => "amqp",
        (Protocol::Tcp, 5900) => "vnc",
        (Protocol::Tcp, 6379) => "redis",
        (Protocol::Tcp, 6443) => "kubernetes",
        (Protocol::Tcp, 8080) => "http-proxy",
        (Protocol::Tcp, 8443) => "https-alt",
        (Protocol::Tcp, 9200) => "elasticsearch",
        (_, 11211) => "memcache",
        (Protocol::Tcp, 27017) => "mongodb",
        _ => more_service_name(protocol, port).unwrap_or("unknown"),
    }
}

/// Names for the rest of the common ports (the default port lists and the
/// industrial ports), so that a closed or filtered port is labelled the way
/// nmap labels it. These are the IANA registry's service names, which nmap's
/// own names follow for these ports.
fn more_service_name(protocol: Protocol, port: u16) -> Option<&'static str> {
    let tcp = protocol == Protocol::Tcp;
    Some(match (tcp, port) {
        (_, 7) => "echo",
        (_, 9) => "discard",
        (_, 13) => "daytime",
        (false, 17) => "qotd",
        (false, 19) => "chargen",
        (true, 26) => "rsftp",
        (_, 37) => "time",
        (false, 49) => "tacacs",
        (true, 79) => "finger",
        (true, 81) => "hosts2-ns",
        (_, 88) => "kerberos-sec",
        (true, 102) => "iso-tsap",
        (true, 106) => "pop3pw",
        (true, 113) => "ident",
        (true, 119) => "nntp",
        (true, 123) => "ntp",
        (false, 135) => "msrpc",
        (false, 139) => "netbios-ssn",
        (true, 144) => "news",
        (true, 161) => "snmp",
        (true, 162) => "snmptrap",
        (false, 177) => "xdmcp",
        (true, 179) => "bgp",
        (_, 199) => "smux",
        (false, 389) => "ldap",
        (_, 427) => "svrloc",
        (false, 443) => "https",
        (true, 444) => "snpp",
        (false, 445) => "microsoft-ds",
        (false, 464) => "kpasswd5",
        (true, 502) => "mbap",
        (true, 513) => "login",
        (false, 513) => "who",
        (true, 514) => "shell",
        (true, 515) => "printer",
        (false, 517) => "talk",
        (false, 518) => "ntalk",
        (false, 520) => "route",
        (false, 521) => "ripng",
        (true, 543) => "klogin",
        (true, 544) => "kshell",
        (false, 546) => "dhcpv6-client",
        (false, 547) => "dhcpv6-server",
        (true, 548) => "afp",
        (true, 554) => "rtsp",
        (false, 623) => "asf-rmcp",
        (_, 631) => "ipp",
        (true, 646) => "ldp",
        (true, 873) => "rsync",
        (true, 990) => "ftps",
        (true, 1110) => "nfsd-status",
        (false, 1194) => "openvpn",
        (false, 1434) => "ms-sql-m",
        (false, 1645) => "radius",
        (false, 1646) => "radacct",
        (false, 1701) => "L2TP",
        (false, 1718) => "h225gatedisc",
        (false, 1719) => "h323gatestat",
        (true, 1720) => "h323q931",
        (true, 1723) => "pptp",
        (true, 1755) => "wms",
        (false, 1812) => "radius",
        (false, 1813) => "radacct",
        (true, 1900) => "upnp",
        (false, 1985) => "hsrp",
        (true, 2000) => "cisco-sccp",
        (true, 2001) => "dc",
        (true, 2121) => "ccproxy-ftp",
        (false, 2123) => "gtp-control",
        (false, 2152) => "gtp-user",
        (_, 2404) => "iec-104",
        (false, 2427) => "mgcp-gateway",
        (true, 2717) => "pn-requester",
        (false, 2727) => "mgcp-callagent",
        (true, 3000) => "ppp",
        (false, 3074) => "xbox",
        (true, 3128) => "squid-http",
        (false, 3283) => "netassistant",
        (false, 3389) => "ms-wbt-server",
        (false, 3478) => "stun",
        (false, 3544) => "teredo",
        (false, 3702) => "ws-discovery",
        (false, 3784) => "bfd-control",
        (true, 4899) => "radmin",
        (_, 5000) => "upnp",
        (false, 5004) => "avt-profile-1",
        (false, 5005) => "avt-profile-2",
        (true, 5009) => "airport-admin",
        (true, 5051) => "ida-agent",
        (_, 5060) => "sip",
        (false, 5093) => "sentinel-lm",
        (true, 5101) => "admdog",
        (true, 5190) => "aol",
        (false, 5351) => "nat-pmp",
        (false, 5355) => "llmnr",
        (true, 5357) => "wsdapi",
        (true, 5631) => "pcanywheredata",
        (false, 5632) => "pcanywherestat",
        (true, 5666) => "nrpe",
        (false, 5683) => "coap",
        (false, 5684) => "coaps",
        (true, 5800) => "vnc-http",
        (true, 5985) => "wsman",
        (true, 5986) => "wsmans",
        (true, 6000) => "X11",
        (true, 6001) => "X11:1",
        (true, 7070) => "realserver",
        (true, 8000) => "http-alt",
        (true, 8008) => "http",
        (true, 8009) => "ajp13",
        (true, 8081) => "blackice-icecap",
        (true, 8883) => "secure-mqtt",
        (true, 8888) => "sun-answerbook",
        (true, 9090) => "zeus-admin",
        (true, 9100) => "jetdirect",
        (true, 9443) => "tungsten-https",
        (false, 9600) => "micromuse-ncpw",
        (true, 9999) => "abyss",
        (true, 10000) => "snet-sensor-mgmt",
        (false, 10000) => "ndmp",
        (false, 17185) => "wdbrpc",
        (_, 20000) => "dnp",
        (false, 27015) => "halflife",
        (true, 32768) => "filenet-tms",
        (false, 32768) => "omad",
        (false, 32769) => "filenet-rpc",
        (false, 33434) => "traceroute",
        (_, 44818) => "EtherNetIP-2",
        (false, 47808) => "bacnet",
        _ => return None,
    })
}

/// SCTP services by port (IANA's registry), falling back to the TCP name,
/// since many services use the same port over both.
fn sctp_service_name(port: u16) -> &'static str {
    match port {
        9 => "discard",
        179 => "bgp",
        1167 => "cisco-ipsla",
        2225 => "rcip-itu",
        2904 => "m2ua",
        2905 => "m3ua",
        2944 => "megaco-h248",
        2945 => "h248-binary",
        3097 => "itu-bicc-stc",
        3565 => "m2pa",
        3863 => "asap-sctp",
        3864 => "asap-sctp-tls",
        3868 => "diameter",
        5060 => "sip",
        5061 => "sip-tls",
        5090 => "car",
        5091 => "cxtp",
        6704 => "frc-hp",
        6705 => "frc-mp",
        6706 => "frc-lp",
        7626 => "simco",
        9900 => "iua",
        9901 => "enrp-sctp",
        9902 => "enrp-sctp-tls",
        14001 => "sua",
        29118 => "sgsap",
        29168 => "sbcap",
        29169 => "iuhsctpassoc",
        36412 => "s1-control",
        36422 => "x2-control",
        36443 => "m2ap",
        36444 => "m3ap",
        38412 => "ng-control",
        38422 => "xw-control",
        38472 => "f1-control",
        other => service_name(Protocol::Tcp, other),
    }
}

/// The keyword IANA's protocol numbers registry gives IP protocol
/// `proto`, in lower case as `-sO` shows it, or "unknown".
pub fn ip_protocol_name(proto: u8) -> &'static str {
    const NAMES: [&str; 146] = [
        "hopopt",
        "icmp",
        "igmp",
        "ggp",
        "ipv4",
        "st",
        "tcp",
        "cbt",
        "egp",
        "igp",
        "bbn-rcc-mon",
        "nvp-ii",
        "pup",
        "argus",
        "emcon",
        "xnet",
        "chaos",
        "udp",
        "mux",
        "dcn-meas",
        "hmp",
        "prm",
        "xns-idp",
        "trunk-1",
        "trunk-2",
        "leaf-1",
        "leaf-2",
        "rdp",
        "irtp",
        "iso-tp4",
        "netblt",
        "mfe-nsp",
        "merit-inp",
        "dccp",
        "3pc",
        "idpr",
        "xtp",
        "ddp",
        "idpr-cmtp",
        "tp++",
        "il",
        "ipv6",
        "sdrp",
        "ipv6-route",
        "ipv6-frag",
        "idrp",
        "rsvp",
        "gre",
        "dsr",
        "bna",
        "esp",
        "ah",
        "i-nlsp",
        "swipe",
        "narp",
        "mobile",
        "tlsp",
        "skip",
        "ipv6-icmp",
        "ipv6-nonxt",
        "ipv6-opts",
        "unknown",
        "cftp",
        "unknown",
        "sat-expak",
        "kryptolan",
        "rvd",
        "ippc",
        "unknown",
        "sat-mon",
        "visa",
        "ipcv",
        "cpnx",
        "cphb",
        "wsn",
        "pvp",
        "br-sat-mon",
        "sun-nd",
        "wb-mon",
        "wb-expak",
        "iso-ip",
        "vmtp",
        "secure-vmtp",
        "vines",
        "ttp",
        "nsfnet-igp",
        "dgp",
        "tcf",
        "eigrp",
        "ospfigp",
        "sprite-rpc",
        "larp",
        "mtp",
        "ax.25",
        "ipip",
        "micp",
        "scc-sp",
        "etherip",
        "encap",
        "unknown",
        "gmtp",
        "ifmp",
        "pnni",
        "pim",
        "aris",
        "scps",
        "qnx",
        "a/n",
        "ipcomp",
        "snp",
        "compaq-peer",
        "ipx-in-ip",
        "vrrp",
        "pgm",
        "unknown",
        "l2tp",
        "ddx",
        "iatp",
        "stp",
        "srp",
        "uti",
        "smp",
        "sm",
        "ptp",
        "isis",
        "fire",
        "crtp",
        "crudp",
        "sscopmce",
        "iplt",
        "sps",
        "pipe",
        "sctp",
        "fc",
        "rsvp-e2e-ignore",
        "mobility-hdr",
        "udplite",
        "mpls-in-ip",
        "manet",
        "hip",
        "shim6",
        "wesp",
        "rohc",
        "ethernet",
        "aggfrag",
        "nsh",
    ];
    NAMES
        .get(usize::from(proto))
        .copied()
        .unwrap_or(match proto {
            253 | 254 => "experimental",
            255 => "reserved",
            _ => "unknown",
        })
}

/// Common SCTP ports, most used first: signalling for telephone and
/// mobile networks (SIGTRAN, Diameter, S1/NG), and services that also
/// run over SCTP. From IANA's registry and published deployments.
pub const TOP_SCTP_PORTS: &[u16] = &[
    80, 3868, 2905, 36412, 38412, 2904, 5060, 5061, 179, 443, 9, 22, 21, 2944, 2945, 3565, 3863,
    3864, 14001, 29118, 29168, 29169, 36422, 36443, 36444, 38422, 38472, 1167, 2225, 3097, 5090,
    5091, 6704, 6705, 6706, 7626, 9900, 9901, 9902, 1720, 1812, 1813, 4739, 5672, 8282, 20049,
    7701, 8471, 9082, 9084, 25471, 30100,
];

/// Like [`top_ports`], for SCTP, starting from [`TOP_SCTP_PORTS`].
pub fn top_sctp_ports(n: usize) -> Vec<u16> {
    top_from(TOP_SCTP_PORTS, n)
}

/// Parse an nmap-style port specification.
///
/// Accepts a comma-separated list of single ports (`22`), ranges (`1-1024`),
/// open-ended ranges (`-1024`, `60000-`) and `-` for all ports (1-65535).
/// The result is sorted and de-duplicated.
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, Error> {
    let mut ports = Vec::new();
    for part in spec.split(',').map(str::trim) {
        if part.is_empty() {
            return Err(Error::InvalidPorts(format!("empty entry in '{spec}'")));
        }
        if let Some((start, end)) = part.split_once('-') {
            let start = if start.is_empty() {
                1
            } else {
                parse_port(start)?
            };
            let end = if end.is_empty() {
                65535
            } else {
                parse_port(end)?
            };
            if start > end {
                return Err(Error::InvalidPorts(format!(
                    "range start is greater than end in '{part}'"
                )));
            }
            ports.extend(start..=end);
        } else {
            ports.push(parse_port(part)?);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

/// TCP, UDP and SCTP ports, and IP protocol numbers, from one nmap-style
/// specification.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortLists {
    pub tcp: Vec<u16>,
    pub udp: Vec<u16>,
    pub sctp: Vec<u16>,
    /// IP protocol numbers for `-sO`. They may be out of range (over
    /// 255): the caller decides, as only `-sO` reads them.
    pub protocols: Vec<u16>,
}

/// Parse a port specification that may name its protocol, like nmap's
/// `-p 22,T:80,U:53,S:2905,161`: `T:` (TCP), `U:` (UDP), `S:` (SCTP) and
/// `P:` (IP protocols, for `-sO`) apply to the ports after them until the
/// next prefix. Values before any prefix apply to every *active* scan
/// family: `port_scan` says a port scan (TCP, UDP or SCTP) is selected, so
/// they are ports (1-65535); `ip_proto` says `-sO` is selected, so they
/// are also IP protocol numbers (0-255). A value valid for one but not the
/// other (`300` as a port, `0` as a protocol) is rejected only for the
/// family it is out of range for. Each list is sorted and de-duplicated.
pub fn parse_port_lists(spec: &str, ip_proto: bool, port_scan: bool) -> Result<PortLists, Error> {
    #[derive(Clone, Copy, PartialEq)]
    enum Proto {
        All,
        Tcp,
        Udp,
        Sctp,
        Ip,
    }
    let mut groups: Vec<(Proto, Vec<&str>)> = Vec::new();
    let mut current = Proto::All;
    for part in spec.split(',').map(str::trim) {
        let prefix = part.get(..2).map(str::to_ascii_uppercase);
        let named = match prefix.as_deref() {
            Some("T:") => Some(Proto::Tcp),
            Some("U:") => Some(Proto::Udp),
            Some("S:") => Some(Proto::Sctp),
            Some("P:") => Some(Proto::Ip),
            _ => None,
        };
        let rest = match named {
            Some(p) => {
                current = p;
                &part[2..]
            }
            None => part,
        };
        match groups.last_mut() {
            Some((proto, parts)) if *proto == current => parts.push(rest),
            _ => groups.push((current, vec![rest])),
        }
    }
    let mut lists = PortLists::default();
    let note = |e| match e {
        Error::InvalidPorts(why) => Error::InvalidPorts(format!("{why} (in '{spec}')")),
        other => other,
    };
    for (proto, parts) in groups {
        let joined = parts.join(",");
        match proto {
            Proto::Tcp => lists.tcp.extend(parse_ports(&joined).map_err(&note)?),
            Proto::Udp => lists.udp.extend(parse_ports(&joined).map_err(&note)?),
            Proto::Sctp => lists.sctp.extend(parse_ports(&joined).map_err(&note)?),
            // `P:` is always IP protocol numbers: 0 is valid, "-" is 0-255.
            Proto::Ip => lists
                .protocols
                .extend(parse_protocols(&joined).map_err(&note)?),
            Proto::All => {
                // Unprefixed values go to each active scan family in its own
                // range. Parse as ports for TCP/UDP/SCTP (and when no scan
                // family is known, to preserve the old port semantics)...
                if port_scan || !ip_proto {
                    let ports = parse_ports(&joined).map_err(&note)?;
                    lists.tcp.extend(&ports);
                    lists.udp.extend(&ports);
                    lists.sctp.extend(&ports);
                }
                // ...and as IP protocol numbers for -sO.
                if ip_proto {
                    lists
                        .protocols
                        .extend(parse_protocols(&joined).map_err(&note)?);
                }
            }
        }
    }
    for list in [
        &mut lists.tcp,
        &mut lists.udp,
        &mut lists.sctp,
        &mut lists.protocols,
    ] {
        list.sort_unstable();
        list.dedup();
    }
    Ok(lists)
}

/// Parse IP protocol numbers for `-sO`, like [`parse_ports`] but from 0,
/// with "-" or an open range ending at 255.
pub fn parse_protocols(spec: &str) -> Result<Vec<u16>, Error> {
    let mut protos = Vec::new();
    for part in spec.split(',').map(str::trim) {
        let num = |s: &str, default: u16| -> Result<u16, Error> {
            if s.is_empty() {
                return Ok(default);
            }
            match s.parse::<u16>() {
                Ok(n) if n <= 255 => Ok(n),
                _ => Err(Error::InvalidPorts(format!(
                    "'{s}' is not an IP protocol number (0-255)"
                ))),
            }
        };
        if part.is_empty() {
            return Err(Error::InvalidPorts(format!("empty entry in '{spec}'")));
        }
        let (start, end) = match part.split_once('-') {
            Some((a, b)) => (num(a, 0)?, num(b, 255)?),
            None => {
                let n = num(part, 0)?;
                (n, n)
            }
        };
        if start > end {
            return Err(Error::InvalidPorts(format!(
                "range start is greater than end in '{part}'"
            )));
        }
        protos.extend(start..=end);
    }
    protos.sort_unstable();
    protos.dedup();
    Ok(protos)
}

/// The `n` most common ports, sorted ascending.
///
/// Takes ports from [`TOP_PORTS`] first; if `n` is larger than that list, the
/// remaining ports are filled in ascending order from 1 up, so the caller always
/// gets `min(n, 65535)` ports.
pub fn top_ports(n: usize) -> Vec<u16> {
    top_from(TOP_PORTS, n)
}

/// Like [`top_ports`], for UDP, starting from [`TOP_UDP_PORTS`].
pub fn top_udp_ports(n: usize) -> Vec<u16> {
    top_from(TOP_UDP_PORTS, n)
}

fn top_from(list: &[u16], n: usize) -> Vec<u16> {
    let n = n.min(65535);
    let mut ports: Vec<u16> = list.iter().copied().take(n).collect();
    if ports.len() < n {
        let known: std::collections::HashSet<u16> = ports.iter().copied().collect();
        let extra = n - ports.len();
        ports.extend((1..=65535).filter(|p| !known.contains(p)).take(extra));
    }
    ports.sort_unstable();
    ports
}

fn parse_port(s: &str) -> Result<u16, Error> {
    match s.trim().parse::<u16>() {
        Ok(0) => Err(Error::InvalidPorts("port 0 is not scannable".into())),
        Ok(p) => Ok(p),
        Err(_) => Err(Error::InvalidPorts(format!("'{s}' is not a valid port"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_and_list() {
        assert_eq!(parse_ports("22").unwrap(), vec![22]);
        assert_eq!(parse_ports("443, 22,80").unwrap(), vec![22, 80, 443]);
    }

    #[test]
    fn ranges() {
        assert_eq!(parse_ports("20-23").unwrap(), vec![20, 21, 22, 23]);
        assert_eq!(parse_ports("-3").unwrap(), vec![1, 2, 3]);
        assert_eq!(parse_ports("65534-").unwrap(), vec![65534, 65535]);
        assert_eq!(parse_ports("-").unwrap().len(), 65535);
    }

    #[test]
    fn dedup_overlapping() {
        assert_eq!(parse_ports("1-3,2,3-4").unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn protocol_prefixes() {
        let l = parse_port_lists("22,T:80,443,U:53,161", true, true).unwrap();
        assert_eq!(l.tcp, vec![22, 80, 443]);
        assert_eq!(l.udp, vec![22, 53, 161]);
        let l = parse_port_lists("U:53,t:1-3", true, true).unwrap();
        assert_eq!(l.tcp, vec![1, 2, 3]);
        assert_eq!(l.udp, vec![53]);
        let l = parse_port_lists("U:-", true, true).unwrap();
        assert!(l.tcp.is_empty());
        assert_eq!(l.udp.len(), 65535);
        let l = parse_port_lists("80,80,T:80", true, true).unwrap();
        assert_eq!((l.tcp, l.udp), (vec![80], vec![80]));
        for bad in ["", "T:", "S:0", "U:0", "T:22,,80", "X:22", "P:256"] {
            assert!(
                parse_port_lists(bad, true, true).is_err(),
                "{bad} should fail"
            );
        }
    }

    #[test]
    fn sctp_and_protocol_prefixes() {
        // With -sO active (ip_proto), the unprefixed 22 is also a protocol.
        let l = parse_port_lists("22,S:2905,P:1,6,17,0", true, true).unwrap();
        assert_eq!(l.tcp, vec![22]);
        assert_eq!(l.sctp, vec![22, 2905]);
        assert_eq!(l.protocols, vec![0, 1, 6, 17, 22]);
        // Without -sO, unprefixed values stay out of the protocols list.
        let l = parse_port_lists("22,P:1,6", false, true).unwrap();
        assert_eq!(l.protocols, vec![1, 6]);
        // -sO alone reads unprefixed values as IP protocols: 0 and "-" are
        // valid there, but a number above 255 is not.
        assert_eq!(
            parse_port_lists("0", true, false).unwrap().protocols,
            vec![0]
        );
        assert_eq!(
            parse_port_lists("-", true, false).unwrap().protocols.len(),
            256
        );
        assert!(parse_port_lists("300", true, false).is_err());
        assert_eq!(parse_protocols("-").unwrap().len(), 256);
        assert_eq!(
            parse_protocols("250-").unwrap(),
            vec![250, 251, 252, 253, 254, 255]
        );
        assert!(parse_protocols("300").is_err());
    }

    #[test]
    fn names_for_ip_protocols_and_sctp_ports() {
        assert_eq!(service_name(Protocol::Ip, 1), "icmp");
        assert_eq!(service_name(Protocol::Ip, 47), "gre");
        assert_eq!(service_name(Protocol::Ip, 50), "esp");
        assert_eq!(service_name(Protocol::Ip, 89), "ospfigp");
        assert_eq!(service_name(Protocol::Ip, 112), "vrrp");
        assert_eq!(service_name(Protocol::Ip, 132), "sctp");
        assert_eq!(service_name(Protocol::Ip, 145), "nsh");
        assert_eq!(service_name(Protocol::Ip, 200), "unknown");
        // nmap's labels for the industrial ports, open or closed.
        assert_eq!(service_name(Protocol::Tcp, 102), "iso-tsap");
        assert_eq!(service_name(Protocol::Tcp, 502), "mbap");
        assert_eq!(service_name(Protocol::Udp, 47808), "bacnet");
        assert_eq!(service_name(Protocol::Udp, 502), "unknown");
        assert_eq!(service_name(Protocol::Ip, 255), "reserved");
        assert_eq!(service_name(Protocol::Sctp, 3868), "diameter");
        assert_eq!(service_name(Protocol::Sctp, 80), "http");
        let top = top_sctp_ports(TOP_SCTP_PORTS.len());
        assert_eq!(top.len(), TOP_SCTP_PORTS.len(), "no duplicates");
    }

    #[test]
    fn rejects_bad_input() {
        for bad in ["", "0", "70000", "abc", "10-5", "22,,80"] {
            assert!(parse_ports(bad).is_err(), "{bad} should fail");
        }
    }

    #[test]
    fn top_lists_have_1000_ranked_ports() {
        for list in [TOP_PORTS, TOP_UDP_PORTS] {
            assert_eq!(list.len(), 1000);
            let mut sorted = list.to_vec();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted.len(), 1000, "duplicate port in a top list");
            assert!(!list.contains(&0));
        }
        // The defaults (1000) are the whole lists; -F (100) their heads.
        let mut tcp = TOP_PORTS.to_vec();
        tcp.sort_unstable();
        assert_eq!(top_ports(1000), tcp);
        let mut fast = TOP_PORTS[..100].to_vec();
        fast.sort_unstable();
        assert_eq!(top_ports(100), fast);
        let mut udp = TOP_UDP_PORTS.to_vec();
        udp.sort_unstable();
        assert_eq!(top_udp_ports(1000), udp);
        // Common services are in -F; the second tier only in the default.
        for p in [22, 80, 443, 445, 1900, 3389, 8080] {
            assert!(top_ports(100).contains(&p), "{p}");
        }
        for p in [636, 1521, 2222, 5901, 7547, 9092, 10250] {
            assert!(
                !top_ports(100).contains(&p) && top_ports(1000).contains(&p),
                "{p}"
            );
        }
        let fast = top_udp_ports(100);
        for p in [53, 67, 69, 123, 137, 161, 500, 514, 1900, 5353, 1194, 51820] {
            assert!(fast.contains(&p), "{p}");
        }
        for p in [3671, 9993, 10001, 19132] {
            assert!(
                !fast.contains(&p) && top_udp_ports(1000).contains(&p),
                "{p}"
            );
        }
    }

    #[test]
    fn top_ports_has_no_duplicates() {
        let mut list = TOP_PORTS.to_vec();
        list.sort_unstable();
        list.dedup();
        assert_eq!(list.len(), TOP_PORTS.len());
        for n in [1, 50, 1000, 70000] {
            let ports = top_ports(n);
            assert_eq!(ports.len(), n.min(65535));
            assert!(ports.windows(2).all(|w| w[0] < w[1]));
        }
        assert_eq!(top_ports(3), vec![23, 80, 443]);
        assert_eq!(top_udp_ports(2), vec![53, 123]);
        assert_eq!(top_udp_ports(1500).len(), 1500);
    }
}
