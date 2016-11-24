# This script was automatically generated from the dsa-1397
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(27621);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1397");
 script_cve_id("CVE-2007-5197");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1397 security update');
 script_set_attribute(attribute: 'description', value:
'An integer overflow in the BigInteger data type implementation has been
discovered in the free .NET runtime Mono.


The oldstable distribution (sarge) doesn\'t contain mono.


For the stable distribution (etch) this problem has been fixed in
version 1.2.2.1-1etch1. A powerpc build will be provided later.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1397');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mono packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1397] DSA-1397-1 mono");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1397-1 mono");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmono-accessibility1.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-accessibility2.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-bytefx0.7.6.1-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-bytefx0.7.6.2-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-c5-1.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-cairo1.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-cairo2.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-corlib1.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-corlib2.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-cscompmgd7.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-cscompmgd8.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-data-tds1.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-data-tds2.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-dev', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-firebirdsql1.7-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-ldap1.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-ldap2.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-microsoft-build2.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-microsoft7.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-microsoft8.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-npgsql1.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-npgsql2.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-oracle1.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-oracle2.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-peapi1.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-peapi2.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-relaxng1.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-relaxng2.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-security1.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-security2.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-sharpzip0.6-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-sharpzip0.84-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-sharpzip2.6-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-sharpzip2.84-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-sqlite1.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-sqlite2.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-system-data1.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-system-data2.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-system-ldap1.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-system-ldap2.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-system-messaging1.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-system-messaging2.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-system-runtime1.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-system-runtime2.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-system-web1.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-system-web2.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-system1.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-system2.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-winforms1.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono-winforms2.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono0', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono1.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'libmono2.0-cil', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'mono', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'mono-common', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'mono-devel', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'mono-gac', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'mono-gmcs', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'mono-jay', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'mono-jit', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'mono-mcs', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'mono-mjs', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'mono-runtime', release: '4.0', reference: '1.2.2.1-1etch1');
deb_check(prefix: 'mono-utils', release: '4.0', reference: '1.2.2.1-1etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
