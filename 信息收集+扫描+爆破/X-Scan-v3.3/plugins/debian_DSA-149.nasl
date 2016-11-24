# This script was automatically generated from the dsa-149
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14986);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "149");
 script_cve_id("CVE-2002-0391");
 script_bugtraq_id(5356);
 script_xref(name: "CERT", value: "192995");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-149 security update');
 script_set_attribute(attribute: 'description', value:
'An integer overflow bug has been discovered in the RPC library used by
GNU libc, which is derived from the SunRPC library.  This bug could be
exploited to gain unauthorized root access to software linking to this
code.  The packages below also fix integer overflows in the malloc
code.  They also contain a fix from Andreas Schwab to reduce
linebuflen in parallel to bumping up the buffer pointer in the NSS DNS
code.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-149');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libc6 packages immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA149] DSA-149-1 glibc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-149-1 glibc");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'glibc-doc', release: '2.2', reference: '2.1.3-24');
deb_check(prefix: 'i18ndata', release: '2.2', reference: '2.1.3-24');
deb_check(prefix: 'libc6', release: '2.2', reference: '2.1.3-24');
deb_check(prefix: 'libc6-dbg', release: '2.2', reference: '2.1.3-24');
deb_check(prefix: 'libc6-dev', release: '2.2', reference: '2.1.3-24');
deb_check(prefix: 'libc6-pic', release: '2.2', reference: '2.1.3-24');
deb_check(prefix: 'libc6-prof', release: '2.2', reference: '2.1.3-24');
deb_check(prefix: 'libc6.1', release: '2.2', reference: '2.1.3-24');
deb_check(prefix: 'libc6.1-dbg', release: '2.2', reference: '2.1.3-24');
deb_check(prefix: 'libc6.1-dev', release: '2.2', reference: '2.1.3-24');
deb_check(prefix: 'libc6.1-pic', release: '2.2', reference: '2.1.3-24');
deb_check(prefix: 'libc6.1-prof', release: '2.2', reference: '2.1.3-24');
deb_check(prefix: 'libnss1-compat', release: '2.2', reference: '2.1.3-24');
deb_check(prefix: 'locales', release: '2.2', reference: '2.1.3-24');
deb_check(prefix: 'nscd', release: '2.2', reference: '2.1.3-24');
deb_check(prefix: 'glibc-doc', release: '3.0', reference: '2.2.5-11.2');
deb_check(prefix: 'libc6', release: '3.0', reference: '2.2.5-11.2');
deb_check(prefix: 'libc6-dbg', release: '3.0', reference: '2.2.5-11.2');
deb_check(prefix: 'libc6-dev', release: '3.0', reference: '2.2.5-11.2');
deb_check(prefix: 'libc6-dev-sparc64', release: '3.0', reference: '2.2.5-11.2');
deb_check(prefix: 'libc6-pic', release: '3.0', reference: '2.2.5-11.2');
deb_check(prefix: 'libc6-prof', release: '3.0', reference: '2.2.5-11.2');
deb_check(prefix: 'libc6-sparc64', release: '3.0', reference: '2.2.5-11.2');
deb_check(prefix: 'libc6.1', release: '3.0', reference: '2.2.5-11.2');
deb_check(prefix: 'libc6.1-dbg', release: '3.0', reference: '2.2.5-11.2');
deb_check(prefix: 'libc6.1-dev', release: '3.0', reference: '2.2.5-11.2');
deb_check(prefix: 'libc6.1-pic', release: '3.0', reference: '2.2.5-11.2');
deb_check(prefix: 'libc6.1-prof', release: '3.0', reference: '2.2.5-11.2');
deb_check(prefix: 'locales', release: '3.0', reference: '2.2.5-11.2');
deb_check(prefix: 'nscd', release: '3.0', reference: '2.2.5-11.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
