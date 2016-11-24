# This script was automatically generated from the dsa-1142
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22684);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1142");
 script_cve_id("CVE-2006-3913");
 script_bugtraq_id(19117);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1142 security update');
 script_set_attribute(attribute: 'description', value:
'Luigi Auriemma discovered missing boundary checks in freeciv, a clone
of the well known Civilisation game, which can be exploited by remote
attackers to cause a denial of service (crash) and possibly execute
arbitrary code.
For the stable distribution (sarge) these problems have been fixed in
version 2.0.1-1sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1142');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your freeciv package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1142] DSA-1142-1 freeciv");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1142-1 freeciv");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'freeciv', release: '3.1', reference: '2.0.1-1sarge2');
deb_check(prefix: 'freeciv-client-gtk', release: '3.1', reference: '2.0.1-1sarge2');
deb_check(prefix: 'freeciv-client-xaw3d', release: '3.1', reference: '2.0.1-1sarge2');
deb_check(prefix: 'freeciv-data', release: '3.1', reference: '2.0.1-1sarge2');
deb_check(prefix: 'freeciv-gtk', release: '3.1', reference: '2.0.1-1sarge2');
deb_check(prefix: 'freeciv-server', release: '3.1', reference: '2.0.1-1sarge2');
deb_check(prefix: 'freeciv-xaw3d', release: '3.1', reference: '2.0.1-1sarge2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
