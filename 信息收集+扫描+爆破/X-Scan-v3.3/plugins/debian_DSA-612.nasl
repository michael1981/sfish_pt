# This script was automatically generated from the dsa-612
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16008);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "612");
 script_cve_id("CVE-2004-1170");
 script_bugtraq_id(11025);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-612 security update');
 script_set_attribute(attribute: 'description', value:
'Rudolf Polzer discovered a vulnerability in a2ps, a converter and
pretty-printer for many formats to PostScript.  The program did not
escape shell meta characters properly which could lead to the
execution of arbitrary commands as a privileged user if a2ps is
installed as a printer filter.
For the stable distribution (woody) this problem has been fixed in
version 4.13b-16woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-612');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your a2ps package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA612] DSA-612-1 a2ps");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-612-1 a2ps");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'a2ps', release: '3.0', reference: '4.13b-16woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
