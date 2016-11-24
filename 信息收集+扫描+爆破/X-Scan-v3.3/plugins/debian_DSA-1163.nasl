# This script was automatically generated from the dsa-1163
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22705);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1163");
 script_cve_id("CVE-2006-3125");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1163 security update');
 script_set_attribute(attribute: 'description', value:
'Michael Gehring discovered several potential out-of-bounds index
accesses in gtetrinet, a multiplayer Tetris-like game, which may allow
a remote server to execute arbitrary code.
For the stable distribution (sarge) these problems have been fixed in
version 0.7.8-1sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1163');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gtetrinet package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1163] DSA-1163-1 gtetrinet");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1163-1 gtetrinet");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gtetrinet', release: '3.1', reference: '0.7.8-1sarge2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
