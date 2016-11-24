# This script was automatically generated from the dsa-926
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22792);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "926");
 script_cve_id("CVE-2005-3535");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-926 security update');
 script_set_attribute(attribute: 'description', value:
'Steve Kemp from the Debian Security Audit Project discovered a buffer
overflow in ketm, an old school 2D-scrolling shooter game, that can be
exploited to execute arbitrary code with group games privileges.
For the old stable distribution (woody) this problem has been fixed in
version 0.0.6-7woody0.
For the stable distribution (sarge) this problem has been fixed in
version 0.0.6-17sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-926');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ketm package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA926] DSA-926-2 ketm");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-926-2 ketm");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ketm', release: '3.0', reference: '0.0.6-7woody0');
deb_check(prefix: 'ketm', release: '3.1', reference: '0.0.6-17sarge1');
deb_check(prefix: 'ketm-data', release: '3.1', reference: '0.0.6-17sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
