# This script was automatically generated from the dsa-1395
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(27577);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1395");
 script_cve_id("CVE-2007-3919");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1395 security update');
 script_set_attribute(attribute: 'description', value:
'Steve Kemp from the Debian Security Audit project discovered that xen-utils,
a collection of XEN administrative tools, used temporary files insecurely
within the xenmon tool allowing local users to truncate arbitrary files.
For the old stable distribution (sarge) this package was not present.
For the stable distribution (etch) this problem has been fixed in version
3.0.3-0-4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1395');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xen-3.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:S/C:N/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1395] DSA-1395-1 xen-utils");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1395-1 xen-utils");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xen-docs-3.0', release: '4.0', reference: '3.0.3-0-4');
deb_check(prefix: 'xen-hypervisor-3.0.3-1-amd64', release: '4.0', reference: '3.0.3-0-4');
deb_check(prefix: 'xen-hypervisor-3.0.3-1-i386', release: '4.0', reference: '3.0.3-0-4');
deb_check(prefix: 'xen-hypervisor-3.0.3-1-i386-pae', release: '4.0', reference: '3.0.3-0-4');
deb_check(prefix: 'xen-ioemu-3.0.3-1', release: '4.0', reference: '3.0.3-0-4');
deb_check(prefix: 'xen-utils-3.0.3-1', release: '4.0', reference: '3.0.3-0-4');
deb_check(prefix: 'xen-utils', release: '4.0', reference: '3.0.3-0-4');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
