# This script was automatically generated from the dsa-1308
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25530);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "1308");
 script_cve_id("CVE-2007-1362", "CVE-2007-2867", "CVE-2007-2868", "CVE-2007-2869", "CVE-2007-2870", "CVE-2007-2871");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1308 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the Iceweasel web
browser, an unbranded version of the Firefox browser. The Common 
Vulnerabilities and Exposures project identifies the following problems:
CVE-2007-1362
    Nicolas Derouet discovered that Iceweasel performs insufficient 
    validation of cookies, which could lead to denial of service.
CVE-2007-2867
    Boris Zbarsky, Eli Friedman, Georgi Guninski, Jesse Ruderman, Martijn
    Wargers and Olli Pettay discovered crashes in the layout engine, which
    might allow the execution of arbitrary code.
CVE-2007-2868
    Brendan Eich, Igor Bukanov, Jesse Ruderman, <q>moz_bug_r_a4</q> and Wladimir Palant
    discovered crashes in the javascript engine, which might allow the execution of
    arbitrary code.
CVE-2007-2869
    <q>Marcel</q> discovered that malicous web sites can cause massive
    resource consumption through the auto completion feature, resulting
    in denial of service.
CVE-2007-2870
    <q>moz_bug_r_a4</q> discovered that adding an event listener through the
     addEventListener() function allows cross-site scripting.
CVE-2007-2871
    Chris Thomas discovered that XUL popups can be abused for spoofing or
    phishing attacks.
Fixes for the oldstable distribution (sarge) are not available. While there
will be another round of security updates for Mozilla products, Debian doesn\'t
have the resources to backport further security fixes to the old Mozilla
products. You\'re strongly encouraged to upgrade to stable as soon as possible.
For the stable distribution (etch) these problems have been fixed in version
2.0.0.4-0etch1. A build for the Alpha architecture is not yet available, it will
be provided later.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1308');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your iceweasel packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1308] DSA-1308-1 iceweasel");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1308-1 iceweasel");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'firefox', release: '4.0', reference: '2.0.0.4-0etch1');
deb_check(prefix: 'firefox-dom-inspector', release: '4.0', reference: '2.0.0.4-0etch1');
deb_check(prefix: 'firefox-gnome-support', release: '4.0', reference: '2.0.0.4-0etch1');
deb_check(prefix: 'iceweasel', release: '4.0', reference: '2.0.0.4-0etch1');
deb_check(prefix: 'iceweasel-dbg', release: '4.0', reference: '2.0.0.4-0etch1');
deb_check(prefix: 'iceweasel-dom-inspector', release: '4.0', reference: '2.0.0.4-0etch1');
deb_check(prefix: 'iceweasel-gnome-support', release: '4.0', reference: '2.0.0.4-0etch1');
deb_check(prefix: 'mozilla-firefox', release: '4.0', reference: '2.0.0.4-0etch1');
deb_check(prefix: 'mozilla-firefox-dom-inspector', release: '4.0', reference: '2.0.0.4-0etch1');
deb_check(prefix: 'mozilla-firefox-gnome-support', release: '4.0', reference: '2.0.0.4-0etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
