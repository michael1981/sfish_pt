# This script was automatically generated from the dsa-310
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15147);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "310");
 script_cve_id("CVE-2003-0385");
 script_bugtraq_id(7838);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-310 security update');
 script_set_attribute(attribute: 'description', value:
'XaoS, a program for displaying fractal images, is installed setuid
root on certain architectures in order to use svgalib, which requires
access to the video hardware.  However, it is not designed for secure
setuid execution, and can be exploited to gain root privileges.
In these updated packages, the setuid bit has been removed from the
xaos binary.  Users who require the svgalib functionality should grant
these privileges only to a trusted group.
This vulnerability is exploitable in version 3.0-18 (potato) on i386
and alpha architectures, and in version 3.0-23 (woody) on the i386
architecture only.
For the stable distribution (woody) this problem has been fixed in
version 3.0-23woody1.
For the old stable distribution (potato) this problem has been fixed
in version 3.0-18potato1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-310');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-310
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA310] DSA-310-1 xaos");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-310-1 xaos");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xaos', release: '2.2', reference: '3.0-18potato1');
deb_check(prefix: 'xaos', release: '3.0', reference: '3.0-23woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
