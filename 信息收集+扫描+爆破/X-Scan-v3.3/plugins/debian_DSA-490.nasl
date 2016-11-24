# This script was automatically generated from the dsa-490
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15327);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "490");
 script_cve_id("CVE-2002-0688");
 script_bugtraq_id(5812);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-490 security update');
 script_set_attribute(attribute: 'description', value:
'A vulnerability has been discovered in the index support of the
ZCatalog plug-in in Zope, an open source web application server.  A
flaw in the security settings of ZCatalog allows anonymous users to
call arbitrary methods of catalog indexes.  The vulnerability also
allows untrusted code to do the same.
For the stable distribution (woody) this problem has been fixed in
version 2.5.1-1woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-490');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your zope package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA490] DSA-490-1 zope");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-490-1 zope");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'zope', release: '3.0', reference: '2.5.1-1woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
