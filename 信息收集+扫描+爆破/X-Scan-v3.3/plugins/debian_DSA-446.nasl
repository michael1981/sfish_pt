# This script was automatically generated from the dsa-446
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15283);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "446");
 script_cve_id("CVE-2004-0160");
 script_bugtraq_id(9713);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-446 security update');
 script_set_attribute(attribute: 'description', value:
'Ulf Härnhammar from the Debian Security Audit Project
discovered a vulnerability in
synaesthesia, a program which represents sounds visually.
synaesthesia created its configuration file while holding root
privileges, allowing a local user to create files owned by root and
writable by the user\'s primary group.  This type of vulnerability can
usually be easily exploited to execute arbitrary code with root
privileges by various means.
For the current stable distribution (woody) this problem has been
fixed in version 2.1-2.1woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-446');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-446
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA446] DSA-446-1 synaesthesia");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-446-1 synaesthesia");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'synaesthesia', release: '3.0', reference: '2.1-2.1woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
