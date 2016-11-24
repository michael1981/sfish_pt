# This script was automatically generated from the dsa-031
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14868);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "031");
 script_cve_id("CVE-2001-0279");
 script_bugtraq_id(2829);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-031 security update');
 script_set_attribute(attribute: 'description', value:
'Todd Miller announced a new version of sudo which corrects
a buffer overflow that could potentially be used to gain root privileges on the
local system. The fix from sudo 1.6.3p6 is available in sudo 1.6.2p2-1potato1
for Debian 2.2 (potato).  
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-031');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-031
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA031] DSA-031-2 sudo");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-031-2 sudo");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'sudo', release: '2.2', reference: '1.6.2p2-1potato1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
