# This script was automatically generated from the dsa-822
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19791);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "822");
 script_cve_id("CVE-2005-2918");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-822 security update');
 script_set_attribute(attribute: 'description', value:
'Eric Romang discovered that gtkdiskfree, a GNOME program that shows
free and used space on filesystems, creates a temporary file in an
insecure fashion.
The old stable distribution (woody) does not contain the gtkdiskfree
package.
For the stable distribution (sarge) this problem has been fixed in
version 1.9.3-4sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-822');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gtkdiskfree package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA822] DSA-822-1 gtkdiskfree");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-822-1 gtkdiskfree");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gtkdiskfree', release: '3.1', reference: '1.9.3-4sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
