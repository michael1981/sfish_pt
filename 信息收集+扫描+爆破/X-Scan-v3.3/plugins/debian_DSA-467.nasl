# This script was automatically generated from the dsa-467
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15304);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "467");
 script_cve_id("CVE-2003-0781", "CVE-2003-0782");
 script_bugtraq_id(8420, 8421);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-467 security update');
 script_set_attribute(attribute: 'description', value:
'Timo Sirainen discovered two vulnerabilities in ecartis, a mailing
list manager.
   Failure to validate user input could lead to
   disclosure of mailing list passwords
   Multiple buffer overflows
For the stable distribution (woody) these problems have been fixed in
version 0.129a+1.0.0-snap20020514-1.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-467');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-467
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA467] DSA-467-1 ecartis");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-467-1 ecartis");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ecartis', release: '3.0', reference: '0.129a+1.0.0-snap20020514-1.2');
deb_check(prefix: 'ecartis-cgi', release: '3.0', reference: '0.129a+1.0.0-snap20020514-1.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
