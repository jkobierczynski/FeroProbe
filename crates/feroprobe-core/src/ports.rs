//! Port specification parsing (nmap-style `-p` syntax).

use crate::Error;
use crate::model::Protocol;

/// The 1000 TCP ports nmap scans by default, most commonly open first: the
/// order of nmap's `nmap-services` frequencies (nmap 7.94), so the default
/// scan, `-F` (the first 100) and `--top-ports N` cover the same ports as
/// nmap's.
#[rustfmt::skip]
pub const TOP_PORTS: &[u16] = &[
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993,
    5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000,
    8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631,
    631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156,
    543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986,
    13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37, 1000, 3001, 5001,
    82, 10010, 1030, 9090, 2107, 1024, 2103, 6004, 1801, 5050, 19, 8031, 1041, 255, 1048, 1049,
    1053, 1054, 1056, 1064, 1065, 2967, 3703, 17, 808, 3689, 1031, 1044, 1071, 5901, 100, 9102,
    1039, 2869, 4001, 5120, 8010, 9000, 2105, 636, 1038, 2601, 1, 7000, 1066, 1069, 625, 311, 280,
    254, 4000, 1761, 5003, 2002, 1998, 2005, 1032, 1050, 6112, 3690, 1521, 2161, 1080, 6002, 2401,
    902, 4045, 787, 7937, 1058, 2383, 32771, 1033, 1040, 1059, 50000, 5555, 10001, 1494, 3, 593,
    2301, 3268, 7938, 1022, 1234, 1035, 1036, 1037, 1074, 8002, 9001, 464, 497, 1935, 2003, 6666,
    6543, 24, 1352, 3269, 1111, 407, 500, 20, 2006, 1034, 1218, 3260, 15000, 4444, 264, 33, 2004,
    1042, 42510, 999, 3052, 1023, 222, 1068, 888, 7100, 563, 1717, 992, 2008, 32770, 7001, 32772,
    2007, 8082, 5550, 512, 1043, 2009, 5801, 1700, 2701, 7019, 50001, 4662, 2065, 42, 2010, 161,
    2602, 3333, 9535, 5100, 2604, 4002, 5002, 1047, 1051, 1052, 1055, 1060, 1062, 1311, 2702, 3283,
    4443, 5225, 5226, 6059, 6789, 8089, 8192, 8193, 8194, 8651, 8652, 8701, 9415, 9593, 9594, 9595,
    16992, 16993, 20828, 23502, 32769, 33354, 35500, 52869, 55555, 55600, 64623, 64680, 65000,
    65389, 1067, 13782, 366, 5902, 9050, 85, 1002, 5500, 1863, 1864, 5431, 8085, 10243, 45100,
    49999, 51103, 49, 90, 6667, 1503, 6881, 27000, 340, 1500, 8021, 2222, 5566, 8088, 8899, 9071,
    1501, 5102, 6005, 9101, 9876, 32773, 32774, 163, 5679, 146, 648, 1666, 901, 83, 3476, 5004,
    5214, 8001, 8083, 8084, 9207, 14238, 30, 912, 12345, 2030, 2605, 6, 541, 4, 1248, 3005, 8007,
    306, 880, 2500, 1086, 1088, 1097, 2525, 4242, 8291, 9009, 52822, 900, 6101, 2809, 7200, 211,
    800, 987, 1083, 12000, 32775, 705, 711, 20005, 6969, 13783, 1045, 1046, 1057, 1061, 1063, 1070,
    1072, 1073, 1075, 1077, 1078, 1079, 1081, 1082, 1085, 1093, 1094, 1096, 1098, 1099, 1100, 1104,
    1106, 1107, 1108, 1148, 1169, 1272, 1310, 1687, 1718, 1783, 1840, 1947, 2100, 2119, 2135, 2144,
    2160, 2190, 2260, 2381, 2399, 2492, 2607, 2718, 2811, 2875, 3017, 3031, 3071, 3211, 3300, 3301,
    3323, 3325, 3351, 3367, 3404, 3551, 3580, 3659, 3766, 3784, 3801, 3827, 3998, 4003, 4126, 4129,
    4449, 5030, 5222, 5269, 5414, 5633, 5718, 5810, 5825, 5877, 5910, 5911, 5925, 5959, 5960, 5961,
    5962, 5987, 5988, 5989, 6123, 6129, 6156, 6389, 6580, 6788, 6901, 7106, 7625, 7627, 7741, 7777,
    7778, 7911, 8086, 8087, 8181, 8222, 8333, 8400, 8402, 8600, 8649, 8873, 8994, 9002, 9010, 9011,
    9080, 9220, 9290, 9485, 9500, 9502, 9503, 9618, 9900, 9968, 10002, 10012, 10024, 10025, 10566,
    10616, 10617, 10621, 10626, 10628, 10629, 11110, 11967, 13456, 14000, 14442, 15002, 15003,
    15660, 16001, 16016, 16018, 17988, 19101, 19801, 19842, 20000, 20031, 20221, 20222, 21571,
    22939, 24800, 25734, 27715, 28201, 30000, 30718, 31038, 32781, 32782, 33899, 34571, 34572,
    34573, 40193, 48080, 49158, 49159, 49160, 50003, 50006, 50800, 57294, 58080, 60020, 63331,
    65129, 89, 691, 212, 1001, 1999, 2020, 32776, 2998, 6003, 7002, 50002, 32, 898, 2033, 3372,
    5510, 99, 425, 749, 5903, 43, 458, 5405, 6106, 6502, 7007, 13722, 1087, 1089, 1124, 1152, 1183,
    1186, 1247, 1296, 1334, 1580, 1782, 2126, 2179, 2191, 2251, 2522, 3011, 3030, 3077, 3261, 3369,
    3370, 3371, 3493, 3546, 3737, 3828, 3851, 3871, 3880, 3918, 3995, 4006, 4111, 4446, 5054, 5200,
    5280, 5298, 5822, 5859, 5904, 5915, 5922, 5963, 7103, 7402, 7435, 7443, 7512, 8011, 8090, 8100,
    8180, 8254, 8500, 8654, 9091, 9110, 9666, 9877, 9943, 9944, 9998, 10004, 10778, 15742, 16012,
    18988, 19283, 19315, 19780, 24444, 27352, 27353, 27355, 32784, 49163, 49165, 49175, 50389,
    50636, 51493, 55055, 56738, 61532, 61900, 62078, 1021, 9040, 32777, 32779, 616, 666, 700, 2021,
    32778, 84, 545, 1112, 1524, 2040, 4321, 5802, 38292, 49400, 1084, 1600, 2048, 2111, 3006,
    32780, 2638, 6547, 6699, 9111, 16080, 555, 667, 720, 801, 1443, 1533, 2034, 2106, 5560, 6007,
    1090, 1091, 1114, 1117, 1119, 1122, 1131, 1138, 1151, 1175, 1199, 1201, 1271, 1862, 2323, 2393,
    2394, 2608, 2725, 2909, 3003, 3168, 3221, 3322, 3324, 3390, 3517, 3527, 3800, 3809, 3814, 3826,
    3869, 3878, 3889, 3905, 3914, 3920, 3945, 3971, 4004, 4005, 4279, 4445, 4550, 4567, 4848, 4900,
    5033, 5061, 5080, 5087, 5221, 5440, 5544, 5678, 5730, 5811, 5815, 5850, 5862, 5906, 5907, 5950,
    5952, 6025, 6100, 6510, 6565, 6566, 6567, 6689, 6692, 6779, 6792, 6839, 7025, 7496, 7676, 7800,
    7920, 7921, 7999, 8022, 8042, 8045, 8093, 8099, 8200, 8290, 8292, 8300, 8383, 8800, 9003, 9081,
    9099, 9200, 9418, 9575, 9878, 9898, 9917, 10003, 10009, 10180, 10215, 11111, 12174, 12265,
    14441, 15004, 16000, 16113, 17877, 18040, 18101, 19350, 25735, 26214, 27356, 30951, 32783,
    32785, 40911, 41511, 44176, 44501, 49161, 49167, 49176, 50300, 50500, 52673, 52848, 54045,
    54328, 55056, 56737, 57797, 60443, 70, 417, 617, 714, 722, 777, 981, 1009, 2022, 4224, 4998,
    6346, 301, 524, 668, 765, 1076, 2041, 5999, 10082, 259, 416, 1007, 1417, 1434, 1984, 2038,
    2068, 4343, 6009, 7004, 44443, 109, 687, 726, 911, 1010, 1461, 2035, 2046, 4125, 6006, 7201,
    9103, 125, 481, 683, 903, 1011, 1455, 2013, 2043, 2047, 6668, 6669, 256, 406, 783, 843, 2042,
    2045, 5998, 9929, 31337, 44442, 1092, 1095, 1102, 1105, 1113, 1121, 1123, 1126, 1130, 1132,
    1137, 1141, 1145, 1147, 1149, 1154, 1163, 1164, 1165, 1166, 1174, 1185, 1187, 1192, 1198, 1213,
    1216, 1217, 1233, 1236, 1244, 1259, 1277, 1287, 1300, 1301, 1309, 1322, 1328, 1556, 1583, 1594,
    1641, 1658, 1688, 1719, 1721, 1805, 1812, 1839, 1875, 1914, 1971, 1972, 1974, 2099, 2170, 2196,
    2200, 2288, 2366, 2382, 2557, 2710, 2800, 2910, 2920, 2968, 3007, 3013,
];

/// The 1000 UDP ports nmap scans by default, in the same order as nmap's
/// `--top-ports` (see [`TOP_PORTS`]).
#[rustfmt::skip]
pub const TOP_UDP_PORTS: &[u16] = &[
    631, 161, 137, 123, 138, 1434, 445, 135, 67, 53, 139, 500, 68, 520, 1900, 4500, 514, 49152,
    162, 69, 5353, 111, 49154, 1701, 998, 996, 997, 999, 3283, 49153, 1812, 136, 2222, 2049, 32768,
    5060, 1025, 1433, 3456, 80, 20031, 1026, 7, 1646, 1645, 593, 518, 2048, 626, 1027, 177, 1719,
    427, 497, 4444, 1023, 65024, 19, 9, 49193, 1029, 49, 88, 1028, 17185, 1718, 49186, 2000, 31337,
    49192, 49201, 515, 2223, 443, 49181, 1813, 120, 158, 49200, 3703, 32815, 17, 5000, 32771,
    33281, 1030, 623, 1022, 32769, 5632, 10000, 49156, 49182, 49191, 49194, 9200, 30718, 49185,
    49188, 49190, 49211, 5001, 5355, 32770, 34555, 34861, 37444, 1032, 3130, 4045, 1031, 49158,
    49196, 37, 2967, 4000, 989, 3659, 4672, 34862, 23, 49162, 49187, 49189, 49195, 2148, 41524,
    10080, 32772, 407, 42, 33354, 1034, 49180, 49199, 1001, 3389, 6346, 21, 13, 517, 1068, 990,
    1041, 1045, 1782, 6001, 19283, 49171, 49179, 49184, 49202, 49205, 49208, 49209, 49210, 9876,
    39213, 800, 389, 464, 1036, 1038, 1039, 1419, 192, 199, 44968, 1008, 49159, 49166, 1024, 1033,
    19682, 22986, 22, 2002, 664, 1021, 11487, 49163, 49165, 49168, 49172, 58002, 1043, 683, 1019,
    1044, 1049, 1885, 3052, 5093, 5351, 6000, 7938, 5500, 16680, 27892, 32773, 35777, 41058, 113,
    49160, 49169, 49174, 52225, 685, 686, 1047, 1056, 1886, 6004, 8193, 38293, 782, 786, 38037,
    32774, 780, 1080, 32775, 682, 983, 1014, 1054, 1066, 2051, 6970, 6971, 9950, 781, 5050, 16832,
    16947, 18449, 19120, 19503, 19616, 20019, 20126, 20389, 21383, 22846, 22996, 25375, 27195,
    28547, 29823, 30303, 30365, 31073, 31681, 31891, 33355, 42172, 32779, 49167, 49175, 49198,
    49204, 49212, 49213, 49215, 52503, 53571, 5002, 27015, 5003, 7000, 513, 1485, 684, 1037, 1048,
    1065, 1090, 1761, 9103, 32777, 539, 434, 767, 54321, 3401, 112, 512, 1000, 6347, 363, 32818,
    32931, 33744, 34125, 34892, 35438, 36206, 39888, 40116, 40441, 40708, 40732, 40915, 41081,
    41370, 42508, 45441, 47624, 38, 776, 32776, 49157, 49161, 49170, 49173, 49176, 49197, 49207,
    49503, 50612, 51717, 54281, 56141, 58631, 58640, 61370, 62287, 63555, 64513, 217, 775, 1012,
    643, 687, 688, 829, 902, 959, 1035, 1040, 1042, 1064, 1069, 1901, 2160, 3702, 8001, 8181, 9020,
    9199, 16402, 16430, 16918, 17091, 17455, 17459, 17573, 17615, 17616, 17888, 17939, 17989,
    18004, 18234, 18331, 18360, 18582, 18835, 18980, 19017, 19039, 19130, 19165, 19197, 19294,
    19322, 19332, 19489, 19600, 19687, 19933, 20004, 20359, 21131, 21212, 21261, 21298, 21354,
    21621, 21803, 21902, 22055, 22341, 22692, 22695, 22739, 22799, 22914, 23040, 23176, 23354,
    23531, 23557, 23608, 23679, 23781, 23965, 23980, 24007, 24279, 24511, 24594, 24606, 24644,
    24854, 24910, 25003, 25157, 25240, 25280, 25337, 25462, 25541, 25546, 25709, 25931, 26407,
    26415, 26720, 26872, 26966, 27473, 27482, 27707, 27899, 28122, 28369, 28465, 28493, 28543,
    28641, 28840, 28973, 29078, 29243, 29256, 29810, 29977, 30263, 30544, 30656, 30697, 30704,
    30975, 31059, 31109, 31189, 31195, 31365, 31625, 31731, 32345, 32385, 32528, 1346, 20, 2,
    32780, 772, 1214, 1993, 402, 773, 31335, 774, 814, 838, 903, 965, 1007, 1046, 1050, 1053, 1055,
    1057, 1060, 1081, 1100, 1105, 1124, 1234, 1804, 2343, 3664, 6002, 6050, 8000, 8010, 9000, 9001,
    9877, 1059, 1524, 5555, 5010, 32778, 27444, 32798, 33030, 33249, 33459, 33717, 33866, 33872,
    34038, 34079, 34358, 34422, 34433, 34570, 34577, 34578, 34579, 34580, 34758, 34796, 34855,
    35702, 35794, 36108, 36384, 36458, 36489, 36669, 36778, 36893, 36945, 37144, 37212, 37393,
    37602, 37761, 37783, 37813, 37843, 38063, 38412, 38498, 38615, 39217, 39632, 39683, 39714,
    39723, 40019, 40539, 40622, 40711, 40724, 40805, 40847, 40866, 41308, 41446, 41638, 41702,
    41774, 41896, 41967, 41971, 42056, 42313, 42431, 42434, 42557, 42577, 42627, 42639, 43094,
    43195, 43370, 43514, 43686, 43824, 43967, 44101, 44160, 44179, 44185, 44190, 44253, 44334,
    44508, 44923, 44946, 45247, 45380, 45685, 45722, 45818, 45928, 46093, 46532, 46836, 47765,
    47772, 47808, 47915, 47981, 48078, 48189, 48255, 48455, 48489, 48761, 1484, 3, 1067, 49155,
    49177, 49178, 49214, 49216, 49220, 49222, 49226, 49259, 49262, 49306, 49350, 49360, 49393,
    49396, 49640, 49968, 50099, 50164, 50497, 50708, 50919, 51255, 51456, 51554, 51586, 51690,
    51905, 51972, 52144, 53006, 53037, 53589, 53838, 54094, 54114, 54711, 54807, 54925, 55043,
    55544, 55587, 57172, 57409, 57410, 57813, 57843, 57958, 57977, 58075, 58178, 58419, 58797,
    59193, 59207, 59765, 59846, 60172, 60381, 60423, 61024, 61142, 61319, 61322, 61412, 61481,
    61550, 61685, 61961, 62154, 62575, 62677, 62699, 62958, 63420, 64080, 64481, 64590, 64727,
    1058, 4666, 559, 3457, 1455, 4008, 207, 764, 1457, 639, 657, 689, 789, 826, 944, 1013, 1020,
    1051, 1070, 1072, 1087, 1088, 1101, 1200, 2161, 2345, 2362, 3296, 3343, 8900, 9370, 16086, 502,
    16420, 16433, 16449, 16498, 16503, 16545, 16548, 16573, 16674, 16697, 16700, 16708, 16711,
    16739, 16766, 16779, 16786, 16816, 16829, 16838, 16839, 16862, 16896, 16912, 16919, 16938,
    16939, 16948, 16970, 16972, 16974, 17006, 17018, 17077, 17101, 17146, 17184, 17205, 17207,
    17219, 17236, 17237, 17282, 17302, 17321, 17331, 17332, 17338, 17359, 17417, 17423, 17424,
    17468, 17487, 17490, 17494, 17505, 17533, 17549, 17580, 17585, 17592, 17605, 17629, 17638,
    17663, 17673, 17674, 17683, 17726, 17754, 17762, 17787, 17814, 17823, 17824, 17836, 17845,
    17946, 18081, 18113, 18134, 18156, 18228, 18250, 18255, 18258, 18319, 18373, 18485, 18543,
    18605, 18617, 18666, 18669, 18676, 18683, 18807, 18818, 18821, 18830, 18832, 18869, 18883,
    18888, 18958, 18985, 18987, 18991, 18994, 18996, 19022, 19047, 19075, 19096, 19140, 19141,
    19154, 19161, 19181, 19193, 19222, 19227, 19273, 19315, 19374, 19415, 19482, 19500, 19504,
    19541, 19605, 19624, 19625, 19632, 19639, 19647, 19650, 19660, 19662, 19663, 19683, 19695,
    19707, 19717, 19718, 19719, 19722, 19728, 19789, 19792, 19935, 19936, 19956, 19995, 19998,
    20003, 20082, 20117, 20120, 20129, 20146, 20154, 20164, 20206, 20217, 20249, 20262, 20279,
    20288, 20309, 20313, 20326, 20360, 20366, 20380, 20409, 20411, 20423, 20424, 20425, 20445,
    20449, 20464, 20465, 20518, 20522, 20525, 20540, 20560, 20665, 20678, 20679, 20710, 20717,
    20742, 20752, 20762, 20791, 20817, 20842, 20848, 20851, 20865, 20872, 20876, 20884, 20919,
    21000, 21016, 21060, 21083, 21104, 21111, 21167, 21186, 21206, 21207, 21247, 21282, 21303,
    21318, 21320, 21333, 21344, 21358, 21360, 21364, 21366, 21405, 21454, 21468, 21476, 21514,
    21524, 21525, 21556, 21566, 21568, 21576, 21609, 21625, 21644, 21649, 21655, 21663, 21674,
    21698, 21702, 21710, 21742, 21780, 21784, 21800, 21834, 21842, 21847, 21868, 21898, 21923,
    21948, 21967, 22029, 22043, 22045, 22053, 22105, 22109, 22123, 22124,
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
        (Protocol::Tcp, 24) => "priv-mail",
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
        (Protocol::Tcp, 2379) => "etcd-client",
        (Protocol::Tcp, 3306) => "mysql",
        (Protocol::Tcp, 3389) => "ms-wbt-server",
        (Protocol::Tcp, 4190) => "sieve",
        (Protocol::Tcp, 4949) => "munin",
        (Protocol::Udp, 4500) => "nat-t-ike",
        (Protocol::Tcp, 5432) => "postgresql",
        (Protocol::Udp, 5353) => "mdns",
        (Protocol::Tcp, 5672) => "amqp",
        (Protocol::Tcp, 5900) => "vnc",
        (Protocol::Tcp, 6379) => "redis",
        (Protocol::Tcp, 6443) => "kubernetes",
        (Protocol::Tcp, 6556) => "checkmk-agent",
        (Protocol::Tcp, 6600) => "mshvlm",
        (Protocol::Tcp, 6667) => "irc",
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
        (_, 464) => "kpasswd5",
        (true, 502) => "mbap",
        (true, 593) => "http-rpc-epmap",
        (true, 636) => "ldapssl",
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
        (true, 3268) => "globalcatLDAP",
        (true, 3269) => "globalcatLDAPssl",
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
        (true, 9389) => "adws",
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
        // nmap's names for banner services, so a closed port reads the same.
        assert_eq!(service_name(Protocol::Tcp, 4949), "munin");
        assert_eq!(service_name(Protocol::Tcp, 6600), "mshvlm");
        assert_eq!(service_name(Protocol::Tcp, 2379), "etcd-client");
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
        // As in nmap: common services in -F, rarer ones only in the default.
        for p in [22, 80, 443, 445, 3389, 8080] {
            assert!(top_ports(100).contains(&p), "{p}");
        }
        for p in [32, 1001, 2260, 3301, 4002, 6006] {
            assert!(
                !top_ports(100).contains(&p) && top_ports(1000).contains(&p),
                "{p}"
            );
        }
        let fast = top_udp_ports(100);
        for p in [53, 67, 69, 123, 137, 161, 500, 514, 1900, 5353] {
            assert!(fast.contains(&p), "{p}");
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
        assert_eq!(top_udp_ports(2), vec![161, 631]);
        assert_eq!(top_udp_ports(1500).len(), 1500);
    }
}
