# This script was automatically generated from the dsa-794
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19564);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "794");
 script_cve_id("CVE-2005-2656");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-794 security update');
 script_set_attribute(attribute: 'description', value:
'Justin Rye noticed that polygen generates precompiled grammar objects
world-writable, which can be exploited by a local attacker to at least
fill up the filesystem.
The old stable distribution (woody) does not contain the polygen package.
For the stable distribution (sarge) this problem has been fixed in
version 1.0.6-7sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-794');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your polygen package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA794] DSA-794-1 polygen");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-794-1 polygen");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'polygen', release: '3.1', reference: '1.0.6-7sarge1');
deb_check(prefix: 'polygen-data', release: '3.1', reference: '1.0.6-7sarge1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
