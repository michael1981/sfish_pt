# This script was automatically generated from the dsa-1777
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(36208);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1777");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1777 security update');
 script_set_attribute(attribute: 'description', value:
'Peter Palfrader discovered that in the Git revision control system,
on some architectures files under /usr/share/git-core/templates/ were
owned by a non-root user. This allows a user with that uid on the local
system to write to these files and possibly escalate their privileges.
This issue only affects the DEC Alpha and MIPS (big and little endian)
architectures.
For the old stable distribution (etch), this problem has been fixed in
version 1.4.4.4-4+etch2.
For the stable distribution (lenny), this problem has been fixed in
version 1.5.6.5-3+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1777');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your git-core package.');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1777] DSA-1777-1 git-core");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1777-1 git-core");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'git-arch', release: '4.0', reference: '1.4.4.4-4+etch2');
deb_check(prefix: 'git-core', release: '4.0', reference: '1.4.4.4-4+etch2');
deb_check(prefix: 'git-cvs', release: '4.0', reference: '1.4.4.4-4+etch2');
deb_check(prefix: 'git-daemon-run', release: '4.0', reference: '1.4.4.4-4+etch2');
deb_check(prefix: 'git-doc', release: '4.0', reference: '1.4.4.4-4+etch2');
deb_check(prefix: 'git-email', release: '4.0', reference: '1.4.4.4-4+etch2');
deb_check(prefix: 'git-svn', release: '4.0', reference: '1.4.4.4-4+etch2');
deb_check(prefix: 'gitk', release: '4.0', reference: '1.4.4.4-4+etch2');
deb_check(prefix: 'gitweb', release: '4.0', reference: '1.4.4.4-4+etch2');
deb_check(prefix: 'git-arch', release: '5.0', reference: '1.5.6.5-3+lenny1');
deb_check(prefix: 'git-core', release: '5.0', reference: '1.5.6.5-3+lenny1');
deb_check(prefix: 'git-cvs', release: '5.0', reference: '1.5.6.5-3+lenny1');
deb_check(prefix: 'git-daemon-run', release: '5.0', reference: '1.5.6.5-3+lenny1');
deb_check(prefix: 'git-doc', release: '5.0', reference: '1.5.6.5-3+lenny1');
deb_check(prefix: 'git-email', release: '5.0', reference: '1.5.6.5-3+lenny1');
deb_check(prefix: 'git-gui', release: '5.0', reference: '1.5.6.5-3+lenny1');
deb_check(prefix: 'git-svn', release: '5.0', reference: '1.5.6.5-3+lenny1');
deb_check(prefix: 'gitk', release: '5.0', reference: '1.5.6.5-3+lenny1');
deb_check(prefix: 'gitweb', release: '5.0', reference: '1.5.6.5-3+lenny1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
