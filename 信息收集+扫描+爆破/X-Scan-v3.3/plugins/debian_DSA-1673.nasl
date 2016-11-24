# This script was automatically generated from the dsa-1673
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(34974);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1673");
 script_cve_id("CVE-2008-3137", "CVE-2008-3138", "CVE-2008-3141", "CVE-2008-3145", "CVE-2008-3933", "CVE-2008-4683", "CVE-2008-4684");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1673 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in network traffic
analyzer Wireshark. The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2008-3137
    The GSM SMS dissector is vulnerable to denial of service.
CVE-2008-3138
    The PANA and KISMET dissectors are vulnerable to denial of service.
CVE-2008-3141
    The RMI dissector could disclose system memory.
CVE-2008-3145
    The packet reassembling module is vulnerable to denial of service.
CVE-2008-3933
    The zlib uncompression module is vulnerable to denial of service.
CVE-2008-4683
    The Bluetooth ACL dissector is vulnerable to denial of service.
CVE-2008-4684
    The PRP and MATE dissectors are vulnerable to denial of service.
CVE-2008-4685
    The Q931 dissector is vulnerable to denial of service.
For the stable distribution (etch), these problems have been fixed in
version 0.99.4-5.etch.3.
For the upcoming stable distribution (lenny), these problems have been
fixed in version 1.0.2-3+lenny2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1673');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your wireshark packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1673] DSA-1673-1 wireshark");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1673-1 wireshark");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ethereal', release: '4.0', reference: '0.99.4-5.etch.3');
deb_check(prefix: 'ethereal-common', release: '4.0', reference: '0.99.4-5.etch.3');
deb_check(prefix: 'ethereal-dev', release: '4.0', reference: '0.99.4-5.etch.3');
deb_check(prefix: 'tethereal', release: '4.0', reference: '0.99.4-5.etch.3');
deb_check(prefix: 'tshark', release: '4.0', reference: '0.99.4-5.etch.3');
deb_check(prefix: 'wireshark', release: '4.0', reference: '0.99.4-5.etch.3');
deb_check(prefix: 'wireshark-common', release: '4.0', reference: '0.99.4-5.etch.3');
deb_check(prefix: 'wireshark-dev', release: '4.0', reference: '0.99.4-5.etch.3');
deb_check(prefix: 'wireshark', release: '5.0', reference: '1.0.2-3+lenny2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
