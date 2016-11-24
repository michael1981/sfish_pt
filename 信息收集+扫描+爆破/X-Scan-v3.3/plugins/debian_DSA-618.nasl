# This script was automatically generated from the dsa-618
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16049);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "618");
 script_cve_id("CVE-2004-1025", "CVE-2004-1026");
 script_bugtraq_id(11830);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-618 security update');
 script_set_attribute(attribute: 'description', value:
'Pavel Kankovsky discovered that several overflows found in the libXpm
library were also present in imlib, an imaging library for X and X11.
An attacker could create a carefully crafted image file in such a way
that it could cause an application linked with imlib to execute
arbitrary code when the file was opened by a victim.  The Common
Vulnerabilities and Exposures project identifies the following
problems:
    Multiple heap-based buffer overflows.
    Multiple integer overflows.
For the stable distribution (woody) these problems have been fixed in
version 1.9.14-2woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-618');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your imlib packages immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA618] DSA-618-1 imlib");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-618-1 imlib");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gdk-imlib-dev', release: '3.0', reference: '1.9.14-2woody2');
deb_check(prefix: 'gdk-imlib1', release: '3.0', reference: '1.9.14-2woody2');
deb_check(prefix: 'imlib-base', release: '3.0', reference: '1.9.14-2woody2');
deb_check(prefix: 'imlib-dev', release: '3.0', reference: '1.9.14-2woody2');
deb_check(prefix: 'imlib-progs', release: '3.0', reference: '1.9.14-2woody2');
deb_check(prefix: 'imlib1', release: '3.0', reference: '1.9.14-2woody2');
deb_check(prefix: 'imlib', release: '3.0', reference: '1.9.14-2woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
