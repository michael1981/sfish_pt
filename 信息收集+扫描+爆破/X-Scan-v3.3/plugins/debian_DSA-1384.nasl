# This script was automatically generated from the dsa-1384
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(26931);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1384");
 script_cve_id("CVE-2007-1320", "CVE-2007-4993");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1384 security update');
 script_set_attribute(attribute: 'description', value:
'Several local vulnerabilities have been discovered in the Xen hypervisor
packages which may lead to the execution of arbitrary code. The Common
Vulnerabilities and Exposures project identifies the following problems:
CVE-2007-4993
   By use of a specially crafted grub configuration file a domU user
  may be able to execute arbitrary code upon the dom0 when pygrub is
  being used.
CVE-2007-1320
   Multiple heap-based buffer overflows in the Cirrus VGA extension,
  provided by QEMU, may allow local users to execute arbitrary code
  via <q>bitblt</q> heap overflow.
For the stable distribution (etch), these problems have been fixed in version
3.0.3-0-3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1384');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xen-utils package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1384] DSA-1384-1 xen-utils");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1384-1 xen-utils");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xen-docs-3.0', release: '4.0', reference: '3.0.3-0-3');
deb_check(prefix: 'xen-hypervisor-3.0.3-1-amd64', release: '4.0', reference: '3.0.3-0-3');
deb_check(prefix: 'xen-hypervisor-3.0.3-1-i386', release: '4.0', reference: '3.0.3-0-3');
deb_check(prefix: 'xen-hypervisor-3.0.3-1-i386-pae', release: '4.0', reference: '3.0.3-0-3');
deb_check(prefix: 'xen-ioemu-3.0.3-1', release: '4.0', reference: '3.0.3-0-3');
deb_check(prefix: 'xen-utils-3.0.3-1', release: '4.0', reference: '3.0.3-0-3');
deb_check(prefix: 'xen-utils', release: '4.0', reference: '3.0.3-0-3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
