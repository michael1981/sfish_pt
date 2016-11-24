# This script was automatically generated from the dsa-301
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15138);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "301");
 script_cve_id("CVE-2001-0928");
 script_bugtraq_id(3594);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-301 security update');
 script_set_attribute(attribute: 'description', value:
'The gtop daemon, used for monitoring remote machines, contains a
buffer overflow which could be used by an attacker to execute
arbitrary code with the privileges of the daemon process.  If started
as root, the daemon process drops root privileges, assuming uid and
gid 99 by default.
This bug was previously fixed in DSA-098, but one of the patches was
not carried over to later versions of libgtop.
For the stable distribution (woody), this problem has been fixed in
version 1.0.13-3.1.
For the old stable distribution (potato), this problem was fixed in
DSA-098.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-301');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-301
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA301] DSA-301-1 libgtop");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-301-1 libgtop");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libgtop-daemon', release: '3.0', reference: '1.0.13-3.1');
deb_check(prefix: 'libgtop-dev', release: '3.0', reference: '1.0.13-3.1');
deb_check(prefix: 'libgtop1', release: '3.0', reference: '1.0.13-3.1');
deb_check(prefix: 'libgtop', release: '3.0', reference: '1.0.13-3.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
