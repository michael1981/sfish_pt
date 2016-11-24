# This script was automatically generated from the dsa-1055
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22597);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1055");
 script_cve_id("CVE-2006-1993");
 script_bugtraq_id(17671);
 script_xref(name: "CERT", value: "866300");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1055 security update');
 script_set_attribute(attribute: 'description', value:
'Martijn Wargers and Nick Mott described crashes of Mozilla due to the
use of a deleted controller context.  In theory this could be abused to
execute malicious code.  Since Mozilla and Firefox share the same
codebase, Firefox may be vulnerable as well.
For the stable distribution (sarge) this problem has been fixed in
version 1.0.4-2sarge7.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1055');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your Mozilla Firefox packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1055] DSA-1055-1 mozilla-firefox");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1055-1 mozilla-firefox");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mozilla-firefox', release: '3.1', reference: '1.0.4-2sarge7');
deb_check(prefix: 'mozilla-firefox-dom-inspector', release: '3.1', reference: '1.0.4-2sarge7');
deb_check(prefix: 'mozilla-firefox-gnome-support', release: '3.1', reference: '1.0.4-2sarge7');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
