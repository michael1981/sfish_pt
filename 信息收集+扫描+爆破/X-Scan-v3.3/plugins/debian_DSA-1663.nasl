# This script was automatically generated from the dsa-1663
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(34720);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1663");
 script_cve_id("CVE-2008-0960", "CVE-2008-2292", "CVE-2008-4309");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1663 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in NET SNMP, a suite of
Simple Network Management Protocol applications. The Common
Vulnerabilities and Exposures project identifies the following problems:
CVE-2008-0960
    Wes Hardaker reported that the SNMPv3 HMAC verification relies on
    the client to specify the HMAC length, which allows spoofing of
    authenticated SNMPv3 packets.
CVE-2008-2292
    John Kortink reported a buffer overflow in the __snprint_value
    function in snmp_get causing a denial of service and potentially
    allowing the execution of arbitrary code via a large OCTETSTRING 
    in an attribute value pair (AVP).
CVE-2008-4309
    It was reported that an integer overflow in the
    netsnmp_create_subtree_cache function in agent/snmp_agent.c allows   
    remote attackers to cause a denial of service attack via a crafted  
    SNMP GETBULK request.
For the stable distribution (etch), these problems has been fixed in
version 5.2.3-7etch4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1663');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your net-snmp package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1663] DSA-1663-1 net-snmp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1663-1 net-snmp");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libsnmp-base', release: '4.0', reference: '5.2.3-7etch4');
deb_check(prefix: 'libsnmp-perl', release: '4.0', reference: '5.2.3-7etch4');
deb_check(prefix: 'libsnmp9', release: '4.0', reference: '5.2.3-7etch4');
deb_check(prefix: 'libsnmp9-dev', release: '4.0', reference: '5.2.3-7etch4');
deb_check(prefix: 'snmp', release: '4.0', reference: '5.2.3-7etch4');
deb_check(prefix: 'snmpd', release: '4.0', reference: '5.2.3-7etch4');
deb_check(prefix: 'tkmib', release: '4.0', reference: '5.2.3-7etch4');
deb_check(prefix: 'net-snmp', release: '4.0', reference: '5.2.3-7etch4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
