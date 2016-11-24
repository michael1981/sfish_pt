# This script was automatically generated from the dsa-113
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14950);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "113");
 script_cve_id("CVE-2002-0062");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-113 security update');
 script_set_attribute(attribute: 'description', value:
'Several buffer overflows were fixed in the "ncurses" library in November
2000.  Unfortunately, one was missed.  This can lead to crashes when using
ncurses applications in large windows.
The Common Vulnerabilities and
Exposures project has assigned the name
CVE-2002-0062 to this issue.
This problem has been fixed for the stable release of Debian in version
5.0-6.0potato2.  The testing and unstable releases contain ncurses 5.2,
which is not affected by this problem.
There are no known exploits for this problem, but we recommend that all
users upgrade ncurses immediately.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-113');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2002/dsa-113
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA113] DSA-113-1 ncurses");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-113-1 ncurses");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libncurses5', release: '2.2', reference: '5.0-6.0potato2');
deb_check(prefix: 'libncurses5-dbg', release: '2.2', reference: '5.0-6.0potato2');
deb_check(prefix: 'libncurses5-dev', release: '2.2', reference: '5.0-6.0potato2');
deb_check(prefix: 'ncurses-base', release: '2.2', reference: '5.0-6.0potato2');
deb_check(prefix: 'ncurses-bin', release: '2.2', reference: '5.0-6.0potato2');
deb_check(prefix: 'ncurses-term', release: '2.2', reference: '5.0-6.0potato2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
