# This script was automatically generated from the dsa-1039
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22581);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1039");
 script_cve_id("CVE-2005-3302", "CVE-2005-4470");
 script_bugtraq_id(15981);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1039 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in blender, a very fast
and versatile 3D modeller/renderer.  The Common Vulnerabilities and
Exposures Project identifies the following problems:
CVE-2005-3302
    Joxean Koret discovered that due to missing input validation a
    provided script is vulnerable to arbitrary command execution.
CVE-2005-4470
    Damian Put discovered a buffer overflow that allows remote
    attackers to cause a denial of service and possibly execute
    arbitrary code.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 2.36-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1039');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your blender package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1039] DSA-1039-1 blender");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1039-1 blender");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'blender', release: '3.1', reference: '2.36-1sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
