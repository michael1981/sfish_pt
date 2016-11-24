# This script was automatically generated from the dsa-584
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15682);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "584");
 script_cve_id("CVE-2004-1006");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-584 security update');
 script_set_attribute(attribute: 'description', value:
'"infamous41md" noticed that the log functions in dhcp 2.x, which is
still distributed in the stable Debian release, contained pass
parameters to function that use format strings.  One use seems to be
exploitable in connection with a malicious DNS server.
For the stable distribution (woody) these problems have been fixed in
version 2.0pl5-11woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-584');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your dhcp package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA584] DSA-584-1 dhcp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-584-1 dhcp");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'dhcp', release: '3.0', reference: '2.0pl5-11woody1');
deb_check(prefix: 'dhcp-client', release: '3.0', reference: '2.0pl5-11woody1');
deb_check(prefix: 'dhcp-relay', release: '3.0', reference: '2.0pl5-11woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
