# This script was automatically generated from the dsa-1791
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38696);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1791");
 script_cve_id("CVE-2009-1482");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1791 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that the AttachFile action in moin, a python clone of
WikiWiki, is prone to cross-site scripting attacks when renaming
attachements or performing other sub-actions.
The oldstable distribution (etch) is not vulnerable.
For the stable distribution (lenny), this problem has been fixed in
version 1.7.1-3+lenny2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1791');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your moin packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1791] DSA-1791-1 moin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1791-1 moin");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'python-moinmoin', release: '5.0', reference: '1.7.1-3+lenny2');
deb_check(prefix: 'moin', release: '5.0', reference: '1.7.1-3+lenny2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
