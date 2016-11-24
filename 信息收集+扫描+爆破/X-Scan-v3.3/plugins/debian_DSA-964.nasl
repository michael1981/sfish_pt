# This script was automatically generated from the dsa-964
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22830);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "964");
 script_cve_id("CVE-2006-0467");
 script_bugtraq_id(16429);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-964 security update');
 script_set_attribute(attribute: 'description', value:
'A problem has been discovered in gnocatan, the computer version of the
settlers of Catan boardgame, that can lead the server and other clients
to exit via an assert, and hence does not permit the execution of
arbitrary code.  The game has been renamed into Pioneers after the
release of Debian sarge.
For the old stable distribution (woody) this problem has been fixed in
version 0.6.1-5woody3.
For the stable distribution (sarge) this problem has been fixed in
version 0.8.1.59-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-964');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gnocatan and pioneers packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA964] DSA-964-1 gnocatan");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-964-1 gnocatan");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gnocatan-client', release: '3.0', reference: '0.6.1-5woody3');
deb_check(prefix: 'gnocatan-data', release: '3.0', reference: '0.6.1-5woody3');
deb_check(prefix: 'gnocatan-help', release: '3.0', reference: '0.6.1-5woody3');
deb_check(prefix: 'gnocatan-server', release: '3.0', reference: '0.6.1-5woody3');
deb_check(prefix: 'gnocatan-ai', release: '3.1', reference: '0.8.1.59-1sarge1');
deb_check(prefix: 'gnocatan-client', release: '3.1', reference: '0.8.1.59-1sarge1');
deb_check(prefix: 'gnocatan-help', release: '3.1', reference: '0.8.1.59-1sarge1');
deb_check(prefix: 'gnocatan-meta-server', release: '3.1', reference: '0.8.1.59-1sarge1');
deb_check(prefix: 'gnocatan-server-console', release: '3.1', reference: '0.8.1.59-1sarge1');
deb_check(prefix: 'gnocatan-server-data', release: '3.1', reference: '0.8.1.59-1sarge1');
deb_check(prefix: 'gnocatan-server-gtk', release: '3.1', reference: '0.8.1.59-1sarge1');
deb_check(prefix: 'gnocatan', release: '3.1', reference: '0.8.1.59-1sarge1');
deb_check(prefix: 'gnocatan', release: '3.0', reference: '0.6.1-5woody3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
