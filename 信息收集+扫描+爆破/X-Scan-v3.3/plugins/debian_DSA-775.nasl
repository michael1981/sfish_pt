# This script was automatically generated from the dsa-775
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19431);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "775");
 script_cve_id("CVE-2004-0718", "CVE-2005-1937");
 script_bugtraq_id(14242);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-775 security update');
 script_set_attribute(attribute: 'description', value:
'A vulnerability has been discovered in Mozilla and Mozilla Firefox
that allows remote attackers to inject arbitrary Javascript from one
page into the frameset of another site.  Thunderbird is not affected
by this and Galeon will be automatically fixed as it uses Mozilla
components.
The old stable distribution (woody) does not contain Mozilla Firefox
packages.
For the stable distribution (sarge) this problem has been fixed in
version 1.0.4-2sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-775');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mozilla-firefox package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA775] DSA-775-1 mozilla-firefox");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-775-1 mozilla-firefox");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mozilla-firefox', release: '3.1', reference: '1.0.4-2sarge1');
deb_check(prefix: 'mozilla-firefox-dom-inspector', release: '3.1', reference: '1.0.4-2sarge1');
deb_check(prefix: 'mozilla-firefox-gnome-support', release: '3.1', reference: '1.0.4-2sarge1');
deb_check(prefix: 'mozilla', release: '3.1', reference: '1.0.4-2sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
