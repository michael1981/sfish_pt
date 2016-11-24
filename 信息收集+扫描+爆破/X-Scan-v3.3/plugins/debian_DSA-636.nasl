# This script was automatically generated from the dsa-636
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16150);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "636");
 script_cve_id("CVE-2004-0968", "CVE-2004-1382");
 script_bugtraq_id(11286);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-636 security update');
 script_set_attribute(attribute: 'description', value:
'Several insecure uses of temporary files have been discovered in
support scripts in the libc6 package which provides the c library for
a GNU/Linux system.  Trustix developers found that the catchsegv
script uses temporary files insecurely.  Openwall developers
discovered insecure temporary files in the glibcbug script.  These
scripts are vulnerable to a symlink attack.
For the stable distribution (woody) these problems have been fixed in
version 2.2.5-11.8.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-636');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libc6 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA636] DSA-636-1 glibc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-636-1 glibc");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'glibc-doc', release: '3.0', reference: '2.2.5-11.8');
deb_check(prefix: 'libc6', release: '3.0', reference: '2.2.5-11.8');
deb_check(prefix: 'libc6-dbg', release: '3.0', reference: '2.2.5-11.8');
deb_check(prefix: 'libc6-dev', release: '3.0', reference: '2.2.5-11.8');
deb_check(prefix: 'libc6-dev-sparc64', release: '3.0', reference: '2.2.5-11.8');
deb_check(prefix: 'libc6-pic', release: '3.0', reference: '2.2.5-11.8');
deb_check(prefix: 'libc6-prof', release: '3.0', reference: '2.2.5-11.8');
deb_check(prefix: 'libc6-sparc64', release: '3.0', reference: '2.2.5-11.8');
deb_check(prefix: 'libc6.1', release: '3.0', reference: '2.2.5-11.8');
deb_check(prefix: 'libc6.1-dbg', release: '3.0', reference: '2.2.5-11.8');
deb_check(prefix: 'libc6.1-dev', release: '3.0', reference: '2.2.5-11.8');
deb_check(prefix: 'libc6.1-pic', release: '3.0', reference: '2.2.5-11.8');
deb_check(prefix: 'libc6.1-prof', release: '3.0', reference: '2.2.5-11.8');
deb_check(prefix: 'locales', release: '3.0', reference: '2.2.5-11.8');
deb_check(prefix: 'nscd', release: '3.0', reference: '2.2.5-11.8');
deb_check(prefix: 'glibc', release: '3.0', reference: '2.2.5-11.8');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
