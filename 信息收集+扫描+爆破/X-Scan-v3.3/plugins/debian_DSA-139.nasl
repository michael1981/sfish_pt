# This script was automatically generated from the dsa-139
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14976);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "139");
 script_cve_id("CVE-2002-0817");
 script_bugtraq_id(5367);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-139 security update');
 script_set_attribute(attribute: 'description', value:
'GOBBLES found an insecure use of format strings in the super package.
The included program super is intended to provide access to certain
system users for particular users and programs, similar to the program
sudo.  Exploiting this format string vulnerability a local user can
gain unauthorized root access.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-139');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your super package immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA139] DSA-139-1 super");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-139-1 super");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'super', release: '2.2', reference: '3.12.2-2.1');
deb_check(prefix: 'super', release: '3.0', reference: '3.16.1-1.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
