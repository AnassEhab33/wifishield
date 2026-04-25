"""
oui_lookup.py - Hardware Vendor Lookup from BSSID (OUI prefix)
Uses a built-in table of the most common WiFi router/AP vendors.
OUI = first 3 octets of MAC address, registered with IEEE.
"""

# Top 100+ most common WiFi vendor OUI prefixes
_OUI_DB = {
    # TP-Link
    "000000": "TP-Link", "0C8268": "TP-Link", "1027F5": "TP-Link",
    "1C61B4": "TP-Link", "1C3BF3": "TP-Link", "2002AF": "TP-Link",
    "244BFE": "TP-Link", "2C4D54": "TP-Link", "30B5C2": "TP-Link",
    "3476C5": "TP-Link", "50C7BF": "TP-Link", "54AF97": "TP-Link",
    "60E327": "TP-Link", "6466B3": "TP-Link", "70085D": "TP-Link",
    "708BCD": "TP-Link", "745FCA": "TP-Link", "7831C1": "TP-Link",
    "807082": "TP-Link", "84169C": "TP-Link", "8C10D4": "TP-Link",
    "900F0A": "TP-Link", "98DAFF": "TP-Link", "A04F99": "TP-Link",
    "A42BB0": "TP-Link", "AC84C6": "TP-Link", "B0487A": "TP-Link",
    "B04FAB": "TP-Link", "B0BE76": "TP-Link", "B4B024": "TP-Link",
    "C40BCB": "TP-Link", "C8D3A3": "TP-Link", "CC32E5": "TP-Link",
    "D8490B": "TP-Link", "DC973B": "TP-Link", "E4BEED": "TP-Link",
    "EC172F": "TP-Link", "F0A731": "TP-Link", "F4EC38": "TP-Link",
    "F81A67": "TP-Link", "FC7516": "TP-Link",

    # Netgear
    "001E2A": "Netgear", "00146C": "Netgear", "20E52A": "Netgear",
    "28C68E": "Netgear", "2CB05D": "Netgear", "344DEA": "Netgear",
    "3C1E04": "Netgear", "4C60DE": "Netgear", "60024E": "Netgear",
    "6CB0CE": "Netgear", "74446C": "Netgear", "7CB5FF": "Netgear",
    "84412B": "Netgear", "88F7C7": "Netgear", "9C3DCF": "Netgear",
    "A040A0": "Netgear", "A41893": "Netgear", "C03F0E": "Netgear",
    "D4578C": "Netgear", "E091F5": "Netgear",

    # Asus
    "001A92": "Asus", "00116B": "Asus", "00E096": "Asus",
    "107B44": "Asus", "1062E5": "Asus", "14DDA9": "Asus",
    "2C56DC": "Asus", "2C4D54": "Asus", "30A8DB": "Asus",
    "38D547": "Asus", "3CB1B8": "Asus", "4CE676": "Asus",
    "50465D": "Asus", "5404A6": "Asus", "58FC4B": "Asus",
    "6045CB": "Asus", "60A44C": "Asus", "70F1A1": "Asus",
    "74D02B": "Asus", "78247D": "Asus", "7C8AE1": "Asus",
    "80301A": "Asus", "88D7F6": "Asus", "9C5C8E": "Asus",
    "A8F7E0": "Asus", "B06EBF": "Asus", "BC5FF4": "Asus",
    "C860EB": "Asus", "D850E6": "Asus", "E03F49": "Asus",
    "F0795E": "Asus", "F4CE46": "Asus",

    # Linksys / Cisco
    "001310": "Cisco/Linksys", "001839": "Cisco/Linksys",
    "003049": "Cisco", "00E099": "Cisco", "002564": "Cisco",
    "1C1D86": "Cisco", "207810": "Cisco", "24B657": "Cisco",
    "2CB8ED": "Cisco", "3C0839": "Linksys", "58CB52": "Linksys",
    "60A10A": "Linksys", "A04C5B": "Linksys", "C03C59": "Linksys",

    # Huawei
    "001E10": "Huawei", "003048": "Huawei", "0026CC": "Huawei",
    "086360": "Huawei", "0CF166": "Huawei", "10C61F": "Huawei",
    "286ED4": "Huawei", "304F75": "Huawei", "3822D6": "Huawei",
    "4C7712": "Huawei", "4CA787": "Huawei", "5498E3": "Huawei",
    "5CA8EA": "Huawei", "68A0F6": "Huawei", "6C8D37": "Huawei",
    "784C71": "Huawei", "7C60B3": "Huawei", "80E82B": "Huawei",
    "A080B8": "Huawei", "A4A55B": "Huawei", "BC7670": "Huawei",
    "C4073F": "Huawei", "CC989E": "Huawei", "D05BB8": "Huawei",
    "D4A951": "Huawei", "E834E5": "Huawei", "F009D7": "Huawei",
    "F4C714": "Huawei", "F80BFE": "Huawei",

    # D-Link
    "00179A": "D-Link", "001CF0": "D-Link", "00265A": "D-Link",
    "0825AD": "D-Link", "1062EB": "D-Link", "1C7EE5": "D-Link",
    "28107B": "D-Link", "2C4E77": "D-Link", "340995": "D-Link",
    "5CD998": "D-Link", "6006E6": "D-Link", "70627F": "D-Link",
    "74DADA": "D-Link", "78320B": "D-Link", "84C9B2": "D-Link",
    "9094E4": "D-Link", "A0AB1B": "D-Link", "B803FC": "D-Link",
    "C4A81D": "D-Link", "C8BE19": "D-Link", "F07D68": "D-Link",

    # Xiaomi
    "001344": "Xiaomi", "0C3214": "Xiaomi", "28E31F": "Xiaomi",
    "34CE0B": "Xiaomi", "4C49E3": "Xiaomi", "50EC50": "Xiaomi",
    "642737": "Xiaomi", "7005EF": "Xiaomi", "74A4B5": "Xiaomi",
    "78DBCA": "Xiaomi", "8CBEBE": "Xiaomi", "A086C6": "Xiaomi",
    "B0E235": "Xiaomi", "D48C39": "Xiaomi", "F06D78": "Xiaomi",
    "F48B32": "Xiaomi",

    # ZTE
    "0022A1": "ZTE", "180F76": "ZTE", "247F3C": "ZTE",
    "2C957F": "ZTE", "34768B": "ZTE", "401BF5": "ZTE",
    "4C0999": "ZTE", "6066E0": "ZTE", "6C5988": "ZTE",
    "7CF91E": "ZTE", "8C1AEB": "ZTE", "902170": "ZTE",
    "C8B473": "ZTE", "D4D2D6": "ZTE", "E01C41": "ZTE",

    # Apple (Airport, etc.)
    "001124": "Apple", "0023DF": "Apple", "0026BB": "Apple",
    "0C1539": "Apple", "1027F5": "Apple", "1499E2": "Apple",
    "1C91BA": "Apple", "200AB0": "Apple", "284A07": "Apple",
    "3CEA4F": "Apple", "40A6D9": "Apple", "4C32E5": "Apple",
    "5C969D": "Apple", "646080": "Apple", "70CD60": "Apple",
    "A4B197": "Apple", "A8667F": "Apple", "C82A14": "Apple",
    "D89E3F": "Apple",

    # Samsung
    "001632": "Samsung", "002637": "Samsung", "20D390": "Samsung",
    "2C0BEB": "Samsung", "3071BF": "Samsung", "38AA3C": "Samsung",
    "4C3C16": "Samsung", "606BBD": "Samsung", "6C2F2C": "Samsung",
    "784FFA": "Samsung", "8425DB": "Samsung", "8C71F8": "Samsung",
    "947540": "Samsung", "A02195": "Samsung", "C8A823": "Samsung",

    # Ubiquiti (UniFi)
    "002722": "Ubiquiti", "04186B": "Ubiquiti", "0418D6": "Ubiquiti",
    "24A43C": "Ubiquiti", "44D9E7": "Ubiquiti", "687212": "Ubiquiti",
    "788A20": "Ubiquiti", "80242A": "Ubiquiti", "DC9FDB": "Ubiquiti",
    "F09FC2": "Ubiquiti",

    # MikroTik
    "001F2A": "MikroTik", "048BBF": "MikroTik", "184472": "MikroTik",
    "2CC842": "MikroTik", "4C5E0C": "MikroTik", "6C3B6B": "MikroTik",
    "74469A": "MikroTik", "B8590A": "MikroTik", "C4AD34": "MikroTik",
    "CC2DE0": "MikroTik", "D4CA6D": "MikroTik", "DC2C6E": "MikroTik",
    "E48D8C": "MikroTik",

    # Tenda
    "C83A35": "Tenda", "1C7430": "Tenda", "6088C2": "Tenda",
    "CC0DE0": "Tenda", "D03C26": "Tenda", "E8DE27": "Tenda",

    # WE (common in Egypt/MENA)
    "044BED": "WE/Telecom", "084FA9": "WE/Telecom",

    # Qualcomm Atheros
    "000AF5": "Qualcomm Atheros", "00037F": "Qualcomm Atheros",

    # Realtek
    "000E8F": "Realtek", "00E04C": "Realtek",
}


def lookup_vendor(bssid: str) -> str:
    """
    Look up AP vendor name from the first 3 octets of the BSSID.
    Returns vendor name string or 'Unknown Vendor'.
    """
    if not bssid or bssid == 'N/A':
        return 'Unknown'
    # Normalize: remove colons/dashes, uppercase
    clean = bssid.replace(':', '').replace('-', '').upper()
    oui = clean[:6]
    return _OUI_DB.get(oui, 'Unknown Vendor')
