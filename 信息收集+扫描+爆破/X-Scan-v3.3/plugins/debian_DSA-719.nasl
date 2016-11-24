# This script was automatically generated from the dsa-719
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18158);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "719");
 script_cve_id("CVE-2005-0523");
 script_bugtraq_id(12635);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-719 security update');
 script_set_attribute(attribute: 'description', value:
'Several format string problems have been discovered in prozilla, a
multi-threaded download accelerator, that can be exploited by a
malicious server to execute arbitrary code with the rights of the user
running prozilla.
For the stable distribution (woody) these problems have been fixed in
version 1.3.6-3woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-719');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your prozilla package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA719] DSA-719-1 prozilla");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-719-1 prozilla");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'prozilla', release: '3.0', reference: '1.3.6-3woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
