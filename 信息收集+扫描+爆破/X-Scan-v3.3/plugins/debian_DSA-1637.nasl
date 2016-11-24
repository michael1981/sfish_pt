# This script was automatically generated from the dsa-1637
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(34212);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1637");
 script_cve_id("CVE-2008-3546");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1637 security update');
 script_set_attribute(attribute: 'description', value:
'Multiple vulnerabilities have been identified in git-core, the core of
the git distributed revision control system.  Improper path length
limitations in git\'s diff and grep functions, in combination with
maliciously crafted repositories or changes, could enable a stack
buffer overflow and potentially the execution of arbitrary code.
The Common Vulnerabilities and Exposures project identifies this
vulnerability as CVE-2008-3546.
For the stable distribution (etch), this problem has been fixed in
version 1.4.4.4-2.1+etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1637');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your git-core packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1637] DSA-1637-1 git-core");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1637-1 git-core");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'git-arch', release: '4.0', reference: '1.4.4.4-2.1+etch1');
deb_check(prefix: 'git-core', release: '4.0', reference: '1.4.4.4-2.1+etch1');
deb_check(prefix: 'git-cvs', release: '4.0', reference: '1.4.4.4-2.1+etch1');
deb_check(prefix: 'git-daemon-run', release: '4.0', reference: '1.4.4.4-2.1+etch1');
deb_check(prefix: 'git-doc', release: '4.0', reference: '1.4.4.4-2.1+etch1');
deb_check(prefix: 'git-email', release: '4.0', reference: '1.4.4.4-2.1+etch1');
deb_check(prefix: 'git-svn', release: '4.0', reference: '1.4.4.4-2.1+etch1');
deb_check(prefix: 'gitk', release: '4.0', reference: '1.4.4.4-2.1+etch1');
deb_check(prefix: 'gitweb', release: '4.0', reference: '1.4.4.4-2.1+etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
