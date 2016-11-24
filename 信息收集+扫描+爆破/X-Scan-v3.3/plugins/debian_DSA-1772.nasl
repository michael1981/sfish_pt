# This script was automatically generated from the dsa-1772
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(36172);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1772");
 script_cve_id("CVE-2009-1185", "CVE-2009-1186");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1772 security update');
 script_set_attribute(attribute: 'description', value:
'Sebastian Kramer discovered two vulnerabilities in udev, the /dev and
hotplug management daemon.
CVE-2009-1185
    udev does not check the origin of NETLINK messages, allowing local
    users to gain root privileges.
CVE-2009-1186
    udev suffers from a buffer overflow condition in path encoding,
    potentially allowing arbitrary code execution.
For the old stable distribution (etch), these problems have been fixed in
version 0.105-4etch1.
For the stable distribution (lenny), these problems have been fixed in
version 0.125-7+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1772');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your udev package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1772] DSA-1772-1 udev");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1772-1 udev");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libvolume-id-dev', release: '4.0', reference: '0.105-4etch1');
deb_check(prefix: 'libvolume-id0', release: '4.0', reference: '0.105-4etch1');
deb_check(prefix: 'udev', release: '4.0', reference: '0.105-4etch1');
deb_check(prefix: 'libvolume-id-dev', release: '5.0', reference: '0.125-7+lenny1');
deb_check(prefix: 'libvolume-id0', release: '5.0', reference: '0.125-7+lenny1');
deb_check(prefix: 'udev', release: '5.0', reference: '0.125-7+lenny1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
