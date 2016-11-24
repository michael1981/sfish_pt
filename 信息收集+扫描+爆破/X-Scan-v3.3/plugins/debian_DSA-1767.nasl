# This script was automatically generated from the dsa-1767
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(36123);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1767");
 script_cve_id("CVE-2009-0115");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1767 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that multipathd of multipath-tools, a tool-chain to manage
disk multipath device maps, uses insecure permissions on its unix domain
control socket which enables local attackers to issue commands to multipathd
prevent access to storage devices or corrupt file system data.
For the oldstable distribution (etch), this problem has been fixed in
version 0.4.7-1.1etch2.
For the stable distribution (lenny), this problem has been fixed in
version 0.4.8-14+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1767');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your multipath-tools packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1767] DSA-1767-1 multipath-tools");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1767-1 multipath-tools");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'multipath-tools', release: '4.0', reference: '0.4.7-1.1etch2');
deb_check(prefix: 'kpartx', release: '5.0', reference: '0.4.8-14+lenny1');
deb_check(prefix: 'multipath-tools', release: '5.0', reference: '0.4.8-14+lenny1');
deb_check(prefix: 'multipath-tools-boot', release: '5.0', reference: '0.4.8-14+lenny1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
