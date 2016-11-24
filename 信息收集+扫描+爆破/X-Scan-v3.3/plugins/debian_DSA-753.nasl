# This script was automatically generated from the dsa-753
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18674);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "753");
 script_cve_id("CVE-2005-1686");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-753 security update');
 script_set_attribute(attribute: 'description', value:
'A format string vulnerability has been discovered in gedit, a
light-weight text editor for GNOME, that may allow attackers to cause
a denial of service (application crash) via a binary file with format
string specifiers in the filename.  Since gedit supports opening files
via "http://" URLs (through GNOME vfs) and other schemes, this might
be a remotely exploitable vulnerability.
The old stable distribution (woody) is not vulnerable to this problem.
For the stable distribution (sarge) this problem has been fixed in
version 2.8.3-4sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-753');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gedit package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA753] DSA-753-1 gedit");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-753-1 gedit");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gedit', release: '3.1', reference: '2.8.3-4sarge1');
deb_check(prefix: 'gedit-common', release: '3.1', reference: '2.8.3-4sarge1');
deb_check(prefix: 'gedit-dev', release: '3.1', reference: '2.8.3-4sarge1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
