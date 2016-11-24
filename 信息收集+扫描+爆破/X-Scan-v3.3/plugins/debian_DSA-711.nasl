# This script was automatically generated from the dsa-711
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18086);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "711");
 script_cve_id("CVE-2004-1341");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-711 security update');
 script_set_attribute(attribute: 'description', value:
'Nicolas Gregoire discovered a cross-site scripting vulnerability in
info2www, a converter for info files to HTML.  A malicious person
could place a harmless looking link on the web that could cause
arbitrary commands to be executed in the browser of the victim user.
For the stable distribution (woody) this problem has been fixed in
version 1.2.2.9-20woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-711');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your info2www package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA711] DSA-711-1 info2www");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-711-1 info2www");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'info2www', release: '3.0', reference: '1.2.2.9-20woody1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
