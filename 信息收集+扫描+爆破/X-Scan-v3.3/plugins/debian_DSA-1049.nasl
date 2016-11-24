# This script was automatically generated from the dsa-1049
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22591);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "1049");
 script_bugtraq_id(17682);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1049 security update');
 script_set_attribute(attribute: 'description', value:
'Gerald Combs reported several vulnerabilities in ethereal, a popular
network traffic analyser.  The Common Vulnerabilities and Exposures
project identifies the following problems:
CVE-2006-1932
    The OID printing routine is susceptible to an off-by-one error.
CVE-2006-1933
     The UMA and BER dissectors could go into an infinite loop.
CVE-2006-1934
    The Network Instruments file code could overrun a buffer.
CVE-2006-1935
    The COPS dissector contains a potential buffer overflow.
CVE-2006-1936
    The telnet dissector contains a buffer overflow.
CVE-2006-1937
    Bugs in the SRVLOC and AIM dissector, and in the statistics
    counter could crash ethereal.
CVE-2006-1938
    Null pointer dereferences in the SMB PIPE dissector and when
    reading a malformed Sniffer capture could crash ethereal.
CVE-2006-1939
    Null pointer dereferences in the ASN.1, GSM SMS, RPC and
    ASN.1-based dissector and an invalid display filter could crash
    ethereal.
CVE-2006-1940
    The SNDCP dissector could cause an unintended abortion.
For the old stable distribution (woody) these problems have been fixed in
version 0.9.4-1woody15.
For the stable distribution (sarge) these problems have been fixed in
version 0.10.10-2sarge5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1049');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ethereal packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1049] DSA-1049-1 ethereal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_cve_id("CVE-2006-1932", "CVE-2006-1933", "CVE-2006-1934", "CVE-2006-1935", "CVE-2006-1936", "CVE-2006-1937", "CVE-2006-1938", "CVE-2006-1939", "CVE-2006-1940");
 script_summary(english: "DSA-1049-1 ethereal");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ethereal', release: '3.0', reference: '0.9.4-1woody15');
deb_check(prefix: 'ethereal-common', release: '3.0', reference: '0.9.4-1woody15');
deb_check(prefix: 'ethereal-dev', release: '3.0', reference: '0.9.4-1woody15');
deb_check(prefix: 'tethereal', release: '3.0', reference: '0.9.4-1woody15');
deb_check(prefix: 'ethereal', release: '3.1', reference: '0.10.10-2sarge5');
deb_check(prefix: 'ethereal-common', release: '3.1', reference: '0.10.10-2sarge5');
deb_check(prefix: 'ethereal-dev', release: '3.1', reference: '0.10.10-2sarge5');
deb_check(prefix: 'tethereal', release: '3.1', reference: '0.10.10-2sarge5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
