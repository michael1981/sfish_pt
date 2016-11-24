# This script was automatically generated from the dsa-123
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14960);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "123");
 script_cve_id("CVE-2002-0467");
 script_bugtraq_id(4176);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-123 security update');
 script_set_attribute(attribute: 'description', value:
'Janusz Niewiadomski and Wojciech Purczynski reported a buffer overflow
in the address_match of listar (a listserv style mailing-list manager).
This has been fixed in version 0.129a-2.potato1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-123');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2002/dsa-123
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA123] DSA-123-1 listar");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-123-1 listar");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'listar', release: '2.2', reference: '0.129a-2.potato1');
deb_check(prefix: 'listar-cgi', release: '2.2', reference: '0.129a-2.potato1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
