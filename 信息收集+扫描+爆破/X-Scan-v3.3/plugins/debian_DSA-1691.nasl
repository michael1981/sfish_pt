# This script was automatically generated from the dsa-1691
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35254);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1691");
 script_cve_id("CVE-2007-3555", "CVE-2008-1502", "CVE-2008-3325", "CVE-2008-3326", "CVE-2008-4796", "CVE-2008-4810", "CVE-2008-4811");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1691 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in Moodle, an online
course management system. The following issues are addressed in this
update, ranging from cross site scripting to remote code execution.
Various cross site scripting issues in the Moodle codebase
(CVE-2008-3326, CVE-2008-3325, CVE-2007-3555, CVE-2008-5432,
MSA-08-0021, MDL-8849, MDL-12793, MDL-11414, MDL-14806,
MDL-10276).
Various cross site request forgery issues in the Moodle codebase
(CVE-2008-3325, MSA-08-0023).
Privilege escalation bugs in the Moodle codebase (MSA-08-0001, MDL-7755).
SQL injection issue in the hotpot module (MSA-08-0010).
An embedded copy of Smarty had several vulnerabilities
(CVE-2008-4811, CVE-2008-4810).
An embedded copy of Snoopy was vulnerable to cross site scripting
(CVE-2008-4796).
An embedded copy of Kses was vulnerable to cross site scripting
(CVE-2008-1502).
For the stable distribution (etch), these problems have been fixed in
version 1.6.3-2+etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1691');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your moodle (1.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1691] DSA-1691-1 moodle");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1691-1 moodle");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'moodle', release: '4.0', reference: '1.6.3-2+etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
