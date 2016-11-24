# This script was automatically generated from the dsa-1128
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22670);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1128");
 script_cve_id("CVE-2006-3815");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1128 security update');
 script_set_attribute(attribute: 'description', value:
'Yan Rong Ge discovered that wrong permissions on a shared memory page
in heartbeat, the subsystem for High-Availability Linux could be
exploited by a local attacker to cause a denial of service.
For the stable distribution (sarge) this problem has been fixed in
version 1.2.3-9sarge5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1128');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your heartbeat packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1128] DSA-1128-1 heartbeat");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1128-1 heartbeat");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'heartbeat', release: '3.1', reference: '1.2.3-9sarge5');
deb_check(prefix: 'heartbeat-dev', release: '3.1', reference: '1.2.3-9sarge5');
deb_check(prefix: 'ldirectord', release: '3.1', reference: '1.2.3-9sarge5');
deb_check(prefix: 'libpils-dev', release: '3.1', reference: '1.2.3-9sarge5');
deb_check(prefix: 'libpils0', release: '3.1', reference: '1.2.3-9sarge5');
deb_check(prefix: 'libstonith-dev', release: '3.1', reference: '1.2.3-9sarge5');
deb_check(prefix: 'libstonith0', release: '3.1', reference: '1.2.3-9sarge5');
deb_check(prefix: 'stonith', release: '3.1', reference: '1.2.3-9sarge5');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
