# This script was automatically generated from the dsa-927
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22793);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "927");
 script_cve_id("CVE-2005-3343");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-927 security update');
 script_set_attribute(attribute: 'description', value:
'The last update of tkdiff contained a programming error which is
fixed by this version.  For completeness we\'re adding the original
advisory text:
Javier Fernández-Sanguino Peña from the Debian Security Audit project
discovered that tkdiff, a graphical side by side "diff" utility,
creates temporary files in an insecure fashion.
For the old stable distribution (woody) this problem has been fixed in
version 3.08-3woody1.
For the stable distribution (sarge) this problem has been fixed in
version 4.0.2-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-927');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your tkdiff package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA927] DSA-927-2 tkdiff");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-927-2 tkdiff");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'tkdiff', release: '3.0', reference: '3.08-3woody1');
deb_check(prefix: 'tkdiff', release: '3.1', reference: '4.0.2-1sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
