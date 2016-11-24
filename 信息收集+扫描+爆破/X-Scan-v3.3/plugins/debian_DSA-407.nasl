# This script was automatically generated from the dsa-407
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15244);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "407");
 script_cve_id("CVE-2003-0925", "CVE-2003-0926", "CVE-2003-0927", "CVE-2003-1012", "CVE-2003-1013");
 script_bugtraq_id(9248, 9249);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-407 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities were discovered upstream in ethereal, a
network traffic analyzer.  The Common Vulnerabilities and Exposures
project identifies the following problems:
A buffer overflow allows remote attackers to cause a denial of
   service and possibly execute arbitrary code via a malformed GTP
   MSISDN string.
Via certain malformed ISAKMP or MEGACO packets remote attackers are
   able to cause a denial of service (crash).
A heap-based buffer overflow allows remote attackers to cause a
   denial of service (crash) and possibly execute arbitrary code via
   the SOCKS dissector.
The SMB dissector allows remote attackers to cause a denial of
   service via a malformed SMB packet that triggers a segmentation
   fault during processing of selected packets.
The Q.931 dissector allows remote attackers to cause a denial of
   service (crash) via a malformed Q.931, which triggers a null
   dereference.
For the stable distribution (woody) this problem has been fixed in
version 0.9.4-1woody6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-407');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ethereal and tethereal packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA407] DSA-407-1 ethereal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-407-1 ethereal");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ethereal', release: '3.0', reference: '0.9.4-1woody6');
deb_check(prefix: 'ethereal-common', release: '3.0', reference: '0.9.4-1woody6');
deb_check(prefix: 'ethereal-dev', release: '3.0', reference: '0.9.4-1woody6');
deb_check(prefix: 'tethereal', release: '3.0', reference: '0.9.4-1woody6');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
