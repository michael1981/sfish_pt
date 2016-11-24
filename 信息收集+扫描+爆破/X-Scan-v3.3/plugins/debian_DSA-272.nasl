# This script was automatically generated from the dsa-272
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15109);
 script_version("$Revision: 1.12 $");
 script_xref(name: "DSA", value: "272");
 script_cve_id("CVE-2003-0028");
 script_bugtraq_id(7123);
 script_xref(name: "CERT", value: "516825");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-272 security update');
 script_set_attribute(attribute: 'description', value:
'eEye Digital Security discovered an integer overflow in the
xdrmem_getbytes() function of glibc, that is also present in dietlibc,
a small libc useful especially for small and embedded systems.  This
function is part of the XDR encoder/decoder derived from Sun\'s RPC
implementation.  Depending upon the application, this vulnerability
can cause buffer overflows and could possibly be exploited to execute
arbitrary code.
For the stable distribution (woody) this problem has been
fixed in version 0.12-2.5.
The old stable distribution (potato) does not contain dietlibc
packages.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-272');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your dietlibc packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA272] DSA-272-1 dietlibc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-272-1 dietlibc");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'dietlibc-dev', release: '3.0', reference: '0.12-2.5');
deb_check(prefix: 'dietlibc-doc', release: '3.0', reference: '0.12-2.5');
deb_check(prefix: 'dietlibc', release: '3.0', reference: '0.12-2.5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
