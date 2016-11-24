# This script was automatically generated from the dsa-039
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14876);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "039");
 script_cve_id("CVE-2001-0169");
 script_bugtraq_id(2223);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-039 security update');
 script_set_attribute(attribute: 'description', value:
'The version of GNU libc that was distributed with Debian
GNU/Linux 2.2 suffered from 2 security problems:


It was possible to use LD_PRELOAD to load libraries that are listed in
/etc/ld.so.cache, even for suid programs. This could be used to create (and
overwrite) files which a user should not be allowed to.
By using LD_PROFILE suid programs would write data to a file to /var/tmp,
which was not done safely. Again, this could be  used to create (and overwrite)
files which a user should not have access to.


Both problems have been fixed in version 2.1.3-17 and we recommend that
you upgrade your glibc packages immediately.

Please note that a side-effect of this upgrade is that ldd will no longer
work on suid programs, unless you logged in as root.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-039');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-039
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA039] DSA-039-1 glibc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-039-1 glibc");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'glibc-doc', release: '2.2', reference: '2.1.3-17');
deb_check(prefix: 'i18ndata', release: '2.2', reference: '2.1.3-17');
deb_check(prefix: 'libc6', release: '2.2', reference: '2.1.3-17');
deb_check(prefix: 'libc6-dbg', release: '2.2', reference: '2.1.3-17');
deb_check(prefix: 'libc6-dev', release: '2.2', reference: '2.1.3-17');
deb_check(prefix: 'libc6-pic', release: '2.2', reference: '2.1.3-17');
deb_check(prefix: 'libc6-prof', release: '2.2', reference: '2.1.3-17');
deb_check(prefix: 'libc6.1', release: '2.2', reference: '2.1.3-17');
deb_check(prefix: 'libc6.1-dbg', release: '2.2', reference: '2.1.3-17');
deb_check(prefix: 'libc6.1-dev', release: '2.2', reference: '2.1.3-17');
deb_check(prefix: 'libc6.1-pic', release: '2.2', reference: '2.1.3-17');
deb_check(prefix: 'libc6.1-prof', release: '2.2', reference: '2.1.3-17');
deb_check(prefix: 'libnss1-compat', release: '2.2', reference: '2.1.3-17');
deb_check(prefix: 'locales', release: '2.2', reference: '2.1.3-17');
deb_check(prefix: 'nscd', release: '2.2', reference: '2.1.3-17');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
