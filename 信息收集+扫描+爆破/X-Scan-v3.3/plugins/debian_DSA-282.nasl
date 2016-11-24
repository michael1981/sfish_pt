# This script was automatically generated from the dsa-282
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15119);
 script_version("$Revision: 1.12 $");
 script_xref(name: "DSA", value: "282");
 script_cve_id("CVE-2003-0028");
 script_bugtraq_id(7123);
 script_xref(name: "CERT", value: "516825");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-282 security update');
 script_set_attribute(attribute: 'description', value:
'eEye Digital Security discovered an integer overflow in the
xdrmem_getbytes() function which is also present in GNU libc.  This
function is part of the XDR (external data representation)
encoder/decoder derived from Sun\'s RPC implementation.  Depending upon
the application, this vulnerability can cause buffer overflows and
could possibly be exploited to execute arbitrary code.
For the stable distribution (woody) this problem has been
fixed in version 2.2.5-11.5.
For the old stable distribution (potato) this problem has been
fixed in version 2.1.3-25.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-282');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libc6 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA282] DSA-282-1 glibc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-282-1 glibc");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'glibc-doc', release: '2.2', reference: '2.1.3-25');
deb_check(prefix: 'i18ndata', release: '2.2', reference: '2.1.3-25');
deb_check(prefix: 'libc6', release: '2.2', reference: '2.1.3-25');
deb_check(prefix: 'libc6-dbg', release: '2.2', reference: '2.1.3-25');
deb_check(prefix: 'libc6-dev', release: '2.2', reference: '2.1.3-25');
deb_check(prefix: 'libc6-pic', release: '2.2', reference: '2.1.3-25');
deb_check(prefix: 'libc6-prof', release: '2.2', reference: '2.1.3-25');
deb_check(prefix: 'libc6.1', release: '2.2', reference: '2.1.3-25');
deb_check(prefix: 'libc6.1-dbg', release: '2.2', reference: '2.1.3-25');
deb_check(prefix: 'libc6.1-dev', release: '2.2', reference: '2.1.3-25');
deb_check(prefix: 'libc6.1-pic', release: '2.2', reference: '2.1.3-25');
deb_check(prefix: 'libc6.1-prof', release: '2.2', reference: '2.1.3-25');
deb_check(prefix: 'libnss1-compat', release: '2.2', reference: '2.1.3-25');
deb_check(prefix: 'locales', release: '2.2', reference: '2.1.3-25');
deb_check(prefix: 'nscd', release: '2.2', reference: '2.1.3-25');
deb_check(prefix: 'glibc-doc', release: '3.0', reference: '2.2.5-11.5');
deb_check(prefix: 'libc6', release: '3.0', reference: '2.2.5-11.5');
deb_check(prefix: 'libc6-dbg', release: '3.0', reference: '2.2.5-11.5');
deb_check(prefix: 'libc6-dev', release: '3.0', reference: '2.2.5-11.5');
deb_check(prefix: 'libc6-dev-sparc64', release: '3.0', reference: '2.2.5-11.5');
deb_check(prefix: 'libc6-pic', release: '3.0', reference: '2.2.5-11.5');
deb_check(prefix: 'libc6-prof', release: '3.0', reference: '2.2.5-11.5');
deb_check(prefix: 'libc6-sparc64', release: '3.0', reference: '2.2.5-11.5');
deb_check(prefix: 'libc6.1', release: '3.0', reference: '2.2.5-11.5');
deb_check(prefix: 'libc6.1-dbg', release: '3.0', reference: '2.2.5-11.5');
deb_check(prefix: 'libc6.1-dev', release: '3.0', reference: '2.2.5-11.5');
deb_check(prefix: 'libc6.1-pic', release: '3.0', reference: '2.2.5-11.5');
deb_check(prefix: 'libc6.1-prof', release: '3.0', reference: '2.2.5-11.5');
deb_check(prefix: 'locales', release: '3.0', reference: '2.2.5-11.5');
deb_check(prefix: 'nscd', release: '3.0', reference: '2.2.5-11.5');
deb_check(prefix: 'glibc', release: '2.2', reference: '2.1.3-25');
deb_check(prefix: 'glibc', release: '3.0', reference: '2.2.5-11.5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
