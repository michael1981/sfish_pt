# This script was automatically generated from the dsa-604
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15899);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "604");
 script_cve_id("CVE-2004-0993");
 script_bugtraq_id(11800);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-604 security update');
 script_set_attribute(attribute: 'description', value:
'"infamous41md" discovered a buffer overflow condition in hpsockd, the
socks server written at Hewlett-Packard.  An exploit could cause the
program to crash or may have worse effect.
For the stable distribution (woody) this problem has been fixed in
version 0.6.woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-604');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your hpsockd package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA604] DSA-604-1 hpsockd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-604-1 hpsockd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'hpsockd', release: '3.0', reference: '0.6.woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
