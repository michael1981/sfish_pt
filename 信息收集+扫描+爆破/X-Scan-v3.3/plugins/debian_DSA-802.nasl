# This script was automatically generated from the dsa-802
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19609);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "802");
 script_cve_id("CVE-2005-2693");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-802 security update');
 script_set_attribute(attribute: 'description', value:
'Marcus Meissner discovered that the cvsbug program from CVS, which
serves the popular Concurrent Versions System, uses temporary files in
an insecure fashion.
For the old stable distribution (woody) this problem has been fixed in
version 1.11.1p1debian-13.
In the stable distribution (sarge) the cvs package does not expose the
cvsbug program anymore.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-802');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your cvs package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA802] DSA-802-1 cvs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-802-1 cvs");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cvs', release: '3.0', reference: '1.11.1p1debian-13');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
