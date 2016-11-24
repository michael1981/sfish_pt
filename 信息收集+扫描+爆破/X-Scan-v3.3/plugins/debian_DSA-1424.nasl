# This script was automatically generated from the dsa-1424
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29259);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1424");
 script_cve_id("CVE-2007-5947", "CVE-2007-5959", "CVE-2007-5960");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1424 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the Iceweasel web
browser, an unbranded version of the Firefox browser. The Common
Vulnerabilities and Exposures project identifies the following problems:
CVE-2007-5947
    Jesse Ruderman and Petko D. Petkov discovered that the URI handler
    for JAR archives allows cross-site scripting.
CVE-2007-5959
    Several crashes in the layout engine were discovered, which might
    allow the execution of arbitrary code.
CVE-2007-5960
    Gregory Fleischer discovered a race condition in the handling of
    the <q>window.location</q> property, which might lead to cross-site
    request forgery.
The Mozilla products in the oldstable distribution (sarge) are no longer
supported with security updates.
For the stable distribution (etch) these problems have been fixed in
version 2.0.0.10-0etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1424');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your iceweasel packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1424] DSA-1424-1 iceweasel");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1424-1 iceweasel");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'firefox', release: '4.0', reference: '2.0.0.10-0etch1');
deb_check(prefix: 'firefox-dom-inspector', release: '4.0', reference: '2.0.0.10-0etch1');
deb_check(prefix: 'firefox-gnome-support', release: '4.0', reference: '2.0.0.10-0etch1');
deb_check(prefix: 'iceweasel', release: '4.0', reference: '2.0.0.10-0etch1');
deb_check(prefix: 'iceweasel-dbg', release: '4.0', reference: '2.0.0.10-0etch1');
deb_check(prefix: 'iceweasel-dom-inspector', release: '4.0', reference: '2.0.0.10-0etch1');
deb_check(prefix: 'iceweasel-gnome-support', release: '4.0', reference: '2.0.0.10-0etch1');
deb_check(prefix: 'mozilla-firefox', release: '4.0', reference: '2.0.0.10-0etch1');
deb_check(prefix: 'mozilla-firefox-dom-inspector', release: '4.0', reference: '2.0.0.10-0etch1');
deb_check(prefix: 'mozilla-firefox-gnome-support', release: '4.0', reference: '2.0.0.10-0etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
