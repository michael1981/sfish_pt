# This script was automatically generated from the dsa-994
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22860);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "994");
 script_cve_id("CVE-2006-0047");
 script_bugtraq_id(16975);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-994 security update');
 script_set_attribute(attribute: 'description', value:
'Luigi Auriemma discovered a denial of service condition in the free
Civilization server that allows a remote user to trigger a server
crash.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 2.0.1-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-994');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your freeciv-server package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA994] DSA-994-1 freeciv");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-994-1 freeciv");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'freeciv', release: '3.1', reference: '2.0.1-1sarge1');
deb_check(prefix: 'freeciv-client-gtk', release: '3.1', reference: '2.0.1-1sarge1');
deb_check(prefix: 'freeciv-client-xaw3d', release: '3.1', reference: '2.0.1-1sarge1');
deb_check(prefix: 'freeciv-data', release: '3.1', reference: '2.0.1-1sarge1');
deb_check(prefix: 'freeciv-gtk', release: '3.1', reference: '2.0.1-1sarge1');
deb_check(prefix: 'freeciv-server', release: '3.1', reference: '2.0.1-1sarge1');
deb_check(prefix: 'freeciv-xaw3d', release: '3.1', reference: '2.0.1-1sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
