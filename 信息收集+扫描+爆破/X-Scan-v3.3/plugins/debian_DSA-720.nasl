# This script was automatically generated from the dsa-720
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18195);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "720");
 script_cve_id("CVE-2005-0157");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-720 security update');
 script_set_attribute(attribute: 'description', value:
'Jeroen van Wolffelaar noticed that the confirm add-on of SmartList,
the listmanager used on lists.debian.org, which is used on that host
as well, could be tricked to subscribe arbitrary addresses to the
lists.
For the stable distribution (woody) this problem has been fixed in
version 3.15-5.woody.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-720');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your smartlist package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA720] DSA-720-1 smartlist");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-720-1 smartlist");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'smartlist', release: '3.0', reference: '3.15-5.woody.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
