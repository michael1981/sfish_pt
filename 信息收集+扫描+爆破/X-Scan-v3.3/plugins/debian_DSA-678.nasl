# This script was automatically generated from the dsa-678
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16382);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "678");
 script_cve_id("CVE-2004-1180");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-678 security update');
 script_set_attribute(attribute: 'description', value:
'"Vlad902" discovered a vulnerability in the rwhod program that can be
used to crash the listening process.  The broadcasting one is
unaffected.  This vulnerability only affects little endian
architectures (i.e. on Debian: alpha, arm, ia64, i386, mipsel,
and s390).
For the stable distribution (woody) this problem has been fixed in
version 0.17-4woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-678');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your rwhod package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA678] DSA-678-1 netkit-rwho");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-678-1 netkit-rwho");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'rwho', release: '3.0', reference: '0.17-4woody2');
deb_check(prefix: 'rwhod', release: '3.0', reference: '0.17-4woody2');
deb_check(prefix: 'netkit-rwho', release: '3.0', reference: '0.17-4woody2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
