# This script was automatically generated from the dsa-1053
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22595);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1053");
 script_cve_id("CVE-2006-1993");
 script_bugtraq_id(17671);
 script_xref(name: "CERT", value: "866300");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1053 security update');
 script_set_attribute(attribute: 'description', value:
'Martijn Wargers and Nick Mott described crashes of Mozilla due to the
use of a deleted controller context.  In theory this could be abused to
execute malicious code.
For the stable distribution (sarge) this problem has been fixed in
version 1.7.8-1sarge6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1053');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mozilla packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1053] DSA-1053-1 mozilla");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1053-1 mozilla");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libnspr-dev', release: '3.1', reference: '1.7.8-1sarge6');
deb_check(prefix: 'libnspr4', release: '3.1', reference: '1.7.8-1sarge6');
deb_check(prefix: 'libnss-dev', release: '3.1', reference: '1.7.8-1sarge6');
deb_check(prefix: 'libnss3', release: '3.1', reference: '1.7.8-1sarge6');
deb_check(prefix: 'mozilla', release: '3.1', reference: '1.7.8-1sarge6');
deb_check(prefix: 'mozilla-browser', release: '3.1', reference: '1.7.8-1sarge6');
deb_check(prefix: 'mozilla-calendar', release: '3.1', reference: '1.7.8-1sarge6');
deb_check(prefix: 'mozilla-chatzilla', release: '3.1', reference: '1.7.8-1sarge6');
deb_check(prefix: 'mozilla-dev', release: '3.1', reference: '1.7.8-1sarge6');
deb_check(prefix: 'mozilla-dom-inspector', release: '3.1', reference: '1.7.8-1sarge6');
deb_check(prefix: 'mozilla-js-debugger', release: '3.1', reference: '1.7.8-1sarge6');
deb_check(prefix: 'mozilla-mailnews', release: '3.1', reference: '1.7.8-1sarge6');
deb_check(prefix: 'mozilla-psm', release: '3.1', reference: '1.7.8-1sarge6');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
