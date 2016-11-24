# This script was automatically generated from the dsa-832
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19801);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "832");
 script_cve_id("CVE-2005-2772");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-832 security update');
 script_set_attribute(attribute: 'description', value:
'Several buffer overflows have been discovered in gopher, a
text-oriented client for the Gopher Distributed Hypertext protocol,
that can be exploited by a malicious Gopher server.
For the old stable distribution (woody) this problem has been fixed in
version 3.0.3woody4.
For the stable distribution (sarge) this problem has been fixed in
version 3.0.7sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-832');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gopher package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA832] DSA-832-1 gopher");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-832-1 gopher");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gopher', release: '3.0', reference: '3.0.3woody4');
deb_check(prefix: 'gopherd', release: '3.0', reference: '3.0.3woody4');
deb_check(prefix: 'gopher', release: '3.1', reference: '3.0.7sarge2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
