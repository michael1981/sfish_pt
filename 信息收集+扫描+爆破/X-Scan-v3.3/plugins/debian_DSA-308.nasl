# This script was automatically generated from the dsa-308
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15145);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "308");
 script_cve_id("CVE-1999-1332", "CVE-2003-0367");
 script_bugtraq_id(7845, 7872);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-308 security update');
 script_set_attribute(attribute: 'description', value:
'Paul Szabo discovered that znew, a script included in the gzip
package, creates its temporary files without taking precautions to
avoid a symlink attack (CVE-2003-0367).
The gzexe script has a similar vulnerability which was patched in an
earlier release but inadvertently reverted.
For the stable distribution (woody) both problems have been fixed in
version 1.3.2-3woody1.
For the old stable distribution (potato) CVE-2003-0367 has been fixed
in version 1.2.4-33.2.  This version is not vulnerable to
CVE-1999-1332 due to an earlier patch.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-308');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-308
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA308] DSA-308-1 gzip");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-308-1 gzip");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gzip', release: '2.2', reference: '1.2.4-33.2');
deb_check(prefix: 'gzip', release: '3.0', reference: '1.3.2-3woody1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
