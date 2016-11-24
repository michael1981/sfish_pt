# This script was automatically generated from the dsa-1011
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22553);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1011");
 script_cve_id("CVE-2005-4347", "CVE-2005-4418");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1011 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in the Debian vserver
support for Linux.  The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2005-4347
    Bjørn Steinbrink discovered that the chroot barrier is not set
    correctly with util-vserver which may result in unauthorised
    escapes from a vserver to the host system.
    This vulnerability is limited to the 2.4 kernel patch included in
    kernel-patch-vserver.  The correction to this problem requires
    updating the util-vserver package as well and installing a new
    kernel built from the updated kernel-patch-vserver package.
CVE-2005-4418
    The default policy of util-vserver is set to trust all unknown
    capabilities instead of considering them as insecure.
The old stable distribution (woody) does not contain a
kernel-patch-vserver package.
For the stable distribution (sarge) this problem has been fixed in
version 1.9.5.5 of kernel-patch-vserver and in version
0.30.204-5sarge3 of util-vserver.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1011');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your util-vserver and
kernel-patch-vserver packages and build a new kernel immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1011] DSA-1011-1 kernel-patch-vserver");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1011-1 kernel-patch-vserver");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kernel-patch-vserver', release: '3.1', reference: '1.9.5.5');
deb_check(prefix: 'util-vserver', release: '3.1', reference: '0.30.204-5sarge3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
