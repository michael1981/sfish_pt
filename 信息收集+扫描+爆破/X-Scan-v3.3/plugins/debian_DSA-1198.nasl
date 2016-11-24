# This script was automatically generated from the dsa-1198
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22907);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1198");
 script_cve_id("CVE-2006-4980");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1198 security update');
 script_set_attribute(attribute: 'description', value:
'Benjamin C. Wiley Sittler discovered that the repr() of the Python 
interpreter allocates insufficient memory when parsing UCS-4 Unicode
strings, which might lead to execution of arbitrary code through
a buffer overflow.
For the stable distribution (sarge) this problem has been fixed in
version 2.3.5-3sarge2. Due to build problems this update lacks fixed
packages for the Alpha and Sparc architectures. Once they are sorted
out, fixed binaries will be released.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1198');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your Python 2.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1198] DSA-1198-1 python2.3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1198-1 python2.3");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'idle-python2.3', release: '3.1', reference: '2.3.5-3sarge2');
deb_check(prefix: 'python2.3', release: '3.1', reference: '2.3.5-3sarge2');
deb_check(prefix: 'python2.3-dev', release: '3.1', reference: '2.3.5-3sarge2');
deb_check(prefix: 'python2.3-doc', release: '3.1', reference: '2.3.5-3sarge2');
deb_check(prefix: 'python2.3-examples', release: '3.1', reference: '2.3.5-3sarge2');
deb_check(prefix: 'python2.3-gdbm', release: '3.1', reference: '2.3.5-3sarge2');
deb_check(prefix: 'python2.3-mpz', release: '3.1', reference: '2.3.5-3sarge2');
deb_check(prefix: 'python2.3-tk', release: '3.1', reference: '2.3.5-3sarge2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
