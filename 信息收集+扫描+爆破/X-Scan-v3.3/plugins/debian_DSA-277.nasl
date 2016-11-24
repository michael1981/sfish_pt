# This script was automatically generated from the dsa-277
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15114);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "277");
 script_cve_id("CVE-2003-0098", "CVE-2003-0099");
 script_bugtraq_id(7200);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-277 security update');
 script_set_attribute(attribute: 'description', value:
'The controlling and management daemon apcupsd for APC\'s Unbreakable
Power Supplies is vulnerable to several buffer overflows and format
string attacks. These bugs can be exploited remotely by an attacker to gain root
access to the machine apcupsd is running on.
For the stable distribution (woody) this problem has been fixed in
version 3.8.5-1.1.1.
For the old stable distribution (potato) this problem does not seem to
exist.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-277');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your apcupsd packages immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA277] DSA-277-1 apcupsd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-277-1 apcupsd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'apcupsd', release: '3.0', reference: '3.8.5-1.1.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
