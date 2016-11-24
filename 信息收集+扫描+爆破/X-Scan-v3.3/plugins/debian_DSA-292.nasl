# This script was automatically generated from the dsa-292
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15129);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "292");
 script_cve_id("CVE-2003-0214");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-292 security update');
 script_set_attribute(attribute: 'description', value:
'Colin Phipps discovered several problems in mime-support, that contains
support programs for the MIME control files \'mime.types\' and \'mailcap\'.
When a temporary file is to be used it is created insecurely, allowing
an attacker to overwrite arbitrary under the user id of the person
executing run-mailcap.
When run-mailcap is executed on a file with a potentially
problematic filename, a temporary file is created (not insecurely
anymore), removed and a symbolic link to this filename is created.  An
attacker could recreate the file before the symbolic link is created,
forcing the display program to display different content.
For the stable distribution (woody) these problems have been fixed in
version 3.18-1.3.
For the old stable distribution (potato) these problems have been
fixed in version 3.9-1.3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-292');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mime-support packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA292] DSA-292-3 mime-support");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-292-3 mime-support");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mime-support', release: '2.2', reference: '3.9-1.3');
deb_check(prefix: 'mime-support', release: '3.0', reference: '3.18-1.3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
