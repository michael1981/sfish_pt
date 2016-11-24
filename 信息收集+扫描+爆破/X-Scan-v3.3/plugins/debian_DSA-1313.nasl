# This script was automatically generated from the dsa-1313
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25557);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1313");
 script_cve_id("CVE-2007-2948");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1313 security update');
 script_set_attribute(attribute: 'description', value:
'Stefan Cornelius and Reimar Doeffinger discovered that the MPlayer movie
player performs insufficient boundary checks when accessing CDDB data,
which might lead to the execution of arbitrary code.
The oldstable distribution (sarge) doesn\'t include MPlayer packages.
For the stable distribution (etch) this problem has been fixed in
version 1.0~rc1-12etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1313');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mplayer package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1313] DSA-1313-1 mplayer");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1313-1 mplayer");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
