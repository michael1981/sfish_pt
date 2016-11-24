# This script was automatically generated from the dsa-761
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19224);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "761");
 script_cve_id("CVE-2005-2231");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-761 security update');
 script_set_attribute(attribute: 'description', value:
'The security update DSA 761-1 for pdns contained a bug which caused a
regression.  This problem is corrected with this advisory.  For
completeness below please find the original advisory text:
Eric Romang discovered several insecure temporary file creations in
heartbeat, the subsystem for High-Availability Linux.
For the old stable distribution (woody) these problems have been fixed in
version 0.4.9.0l-7.3.
For the stable distribution (sarge) these problems have been fixed in
version 1.2.3-9sarge3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-761');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your heartbeat package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA761] DSA-761-2 heartbeat");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-761-2 heartbeat");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'heartbeat', release: '3.0', reference: '0.4.9.0l-7.3');
deb_check(prefix: 'ldirectord', release: '3.0', reference: '0.4.9.0l-7.3');
deb_check(prefix: 'libstonith-dev', release: '3.0', reference: '0.4.9.0l-7.3');
deb_check(prefix: 'libstonith0', release: '3.0', reference: '0.4.9.0l-7.3');
deb_check(prefix: 'stonith', release: '3.0', reference: '0.4.9.0l-7.3');
deb_check(prefix: 'heartbeat', release: '3.1', reference: '1.2.3-9sarge3');
deb_check(prefix: 'heartbeat-dev', release: '3.1', reference: '1.2.3-9sarge3');
deb_check(prefix: 'ldirectord', release: '3.1', reference: '1.2.3-9sarge3');
deb_check(prefix: 'libpils-dev', release: '3.1', reference: '1.2.3-9sarge3');
deb_check(prefix: 'libpils0', release: '3.1', reference: '1.2.3-9sarge3');
deb_check(prefix: 'libstonith-dev', release: '3.1', reference: '1.2.3-9sarge3');
deb_check(prefix: 'libstonith0', release: '3.1', reference: '1.2.3-9sarge3');
deb_check(prefix: 'stonith', release: '3.1', reference: '1.2.3-9sarge3');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
