# This script was automatically generated from the dsa-1277
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25011);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1277");
 script_cve_id("CVE-2007-0653", "CVE-2007-0654");
 script_bugtraq_id(23078);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1277 security update');
 script_set_attribute(attribute: 'description', value:
'Multiple errors have been found in the skin handling routines in xmms,
the X Multimedia System.  These vulnerabilities could allow an
attacker to run arbitrary code as the user running xmms by inducing
the victim to load specially crafted interface skin files.
For the stable distribution (sarge), these problems have been fixed in
version 1.2.10+cvs20050209-2sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1277');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xmms packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1277] DSA-1277-1 XMMS");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1277-1 XMMS");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xmms', release: '3.1', reference: '1.2.10+cvs20050209-2sarge1');
deb_check(prefix: 'xmms-dev', release: '3.1', reference: '1.2.10+cvs20050209-2sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
