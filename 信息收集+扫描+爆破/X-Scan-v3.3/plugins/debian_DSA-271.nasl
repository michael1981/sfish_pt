# This script was automatically generated from the dsa-271
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15108);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "271");
 script_cve_id("CVE-2003-0162");
 script_bugtraq_id(6971);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-271 security update');
 script_set_attribute(attribute: 'description', value:
'A problem has been discovered in ecartis, a mailing list manager,
formerly known as listar.  This vulnerability enables an attacker to
reset the password of any user defined on the list server, including
the list admins.
For the stable distribution (woody) this problem has been fixed in
version 0.129a+1.0.0-snap20020514-1.1 of ecartis.
For the old stable distribution (potato) this problem has been fixed
in version 0.129a-2.potato3 of listar.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-271');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ecartis and listar packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA271] DSA-271-1 ecartis");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-271-1 ecartis");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'listar', release: '2.2', reference: '0.129a-2.potato3');
deb_check(prefix: 'listar-cgi', release: '2.2', reference: '0.129a-2.potato3');
deb_check(prefix: 'ecartis', release: '3.0', reference: '0.129a+1.0.0-snap20020514-1.1');
deb_check(prefix: 'ecartis-cgi', release: '3.0', reference: '0.129a+1.0.0-snap20020514-1.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
