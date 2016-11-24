# This script was automatically generated from the dsa-1077
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22619);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1077");
 script_cve_id("CVE-2004-1617");
 script_bugtraq_id(11443);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1077 security update');
 script_set_attribute(attribute: 'description', value:
'Michal Zalewski discovered that lynx, the popular text-mode WWW
Browser, is not able to grok invalid HTML including a TEXTAREA tag
with a large COLS value and a large tag name in an element that is not
terminated, and loops forever trying to render the broken HTML.  The
same code is present in lynx-ssl.
For the old stable distribution (woody) this problem has been fixed in
version 2.8.4.1b-3.3.
The stable distribution (sarge) does not contain lynx-ssl packages
anymore.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1077');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your lynx-ssl package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1077] DSA-1077-1 lynx-ssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1077-1 lynx-ssl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'lynx-ssl', release: '3.0', reference: '2.8.4.1b-3.3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
