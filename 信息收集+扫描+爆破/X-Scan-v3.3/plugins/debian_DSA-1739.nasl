# This script was automatically generated from the dsa-1739
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35991);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1739");
 script_cve_id("CVE-2009-0753");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1739 security update');
 script_set_attribute(attribute: 'description', value:
'It has been discovered that mldonkey, a client for several P2P
networks, allows attackers to download arbitrary files using crafted
requests to the HTTP console.
The old stable distribution (etch) is not affected by this problem.
For the stable distribution (lenny), this problem has been fixed in
version 2.9.5-2+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1739');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mldonkey packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1739] DSA-1739-1 mldonkey");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1739-1 mldonkey");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mldonkey-gui', release: '5.0', reference: '2.9.5-2+lenny1');
deb_check(prefix: 'mldonkey-server', release: '5.0', reference: '2.9.5-2+lenny1');
deb_check(prefix: 'mldonkey', release: '5.0', reference: '2.9.5-2+lenny1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
