# This script was automatically generated from the dsa-103
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14940);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "103");
 script_cve_id("CVE-2001-0886");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-103 security update');
 script_set_attribute(attribute: 'description', value:
'A buffer overflow has been found in the globbing code for glibc.
This is the code which is used to glob patterns for filenames and is
commonly used in applications like shells and FTP servers.
This has been fixed in version 2.1.3-20 and we recommend that
you upgrade your libc package immediately.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-103');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2002/dsa-103
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA103] DSA-103-1 glibc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-103-1 glibc");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'glibc-doc', release: '2.2', reference: '2.1.3-20');
deb_check(prefix: 'i18ndata', release: '2.2', reference: '2.1.3-20');
deb_check(prefix: 'libc6', release: '2.2', reference: '2.1.3-20');
deb_check(prefix: 'libc6-dbg', release: '2.2', reference: '2.1.3-20');
deb_check(prefix: 'libc6-dev', release: '2.2', reference: '2.1.3-20');
deb_check(prefix: 'libc6-pic', release: '2.2', reference: '2.1.3-20');
deb_check(prefix: 'libc6-prof', release: '2.2', reference: '2.1.3-20');
deb_check(prefix: 'libc6.1', release: '2.2', reference: '2.1.3-20');
deb_check(prefix: 'libc6.1-dbg', release: '2.2', reference: '2.1.3-20');
deb_check(prefix: 'libc6.1-dev', release: '2.2', reference: '2.1.3-20');
deb_check(prefix: 'libc6.1-pic', release: '2.2', reference: '2.1.3-20');
deb_check(prefix: 'libc6.1-prof', release: '2.2', reference: '2.1.3-20');
deb_check(prefix: 'libnss1-compat', release: '2.2', reference: '2.1.3-20');
deb_check(prefix: 'locales', release: '2.2', reference: '2.1.3-20');
deb_check(prefix: 'nscd', release: '2.2', reference: '2.1.3-20');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
