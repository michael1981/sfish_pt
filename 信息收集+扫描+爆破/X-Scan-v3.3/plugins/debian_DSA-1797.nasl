# This script was automatically generated from the dsa-1797
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38724);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1797");
 script_cve_id("CVE-2009-0652", "CVE-2009-1302", "CVE-2009-1303", "CVE-2009-1304", "CVE-2009-1305", "CVE-2009-1306", "CVE-2009-1307");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1797 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in Xulrunner, a 
runtime environment for XUL applications, such as the Iceweasel web
browser. The Common Vulnerabilities and Exposures project identifies
the following problems:
CVE-2009-0652
    Moxie Marlinspike discovered that Unicode box drawing characters inside of
    internationalised domain names could be used for phishing attacks.
CVE-2009-1302
    Olli Pettay, Martijn Wargers, Mats Palmgren, Oleg Romashin, Jesse Ruderman
    and Gary Kwong reported crashes in the layout engine, which might
    allow the execution of arbitrary code.
CVE-2009-1303
    Olli Pettay, Martijn Wargers, Mats Palmgren, Oleg Romashin, Jesse Ruderman
    and Gary Kwong reported crashes in the layout engine, which might
    allow the execution of arbitrary code.
CVE-2009-1304
    Igor Bukanov and Bob Clary discovered crashes in the Javascript engine,
    which might allow the execution of arbitrary code.
CVE-2009-1305
    Igor Bukanov and Bob Clary discovered crashes in the Javascript engine,
    which might allow the execution of arbitrary code.
CVE-2009-1306
    Daniel Veditz discovered that the Content-Disposition: header is ignored
    within the jar: URI scheme.
CVE-2009-1307
    Gregory Fleischer discovered that the same-origin policy for Flash files
    is inproperly enforced for files loaded through the view-source scheme,
    which may result in bypass of cross-domain policy restrictions.
CVE-2009-1308
    Cefn Hoile discovered that sites, which allow the embedding of third-party
    stylesheets are vulnerable to cross-site scripting attacks through XBL
    bindings.
CVE-2009-1309
    "moz_bug_r_a4" discovered bypasses of the same-origin policy in the
    XMLHttpRequest Javascript API and the XPCNativeWrapper.
CVE-2009-1311
    Paolo Amadini discovered that incorrect handling of POST data when
    saving a web site with an embedded frame may lead to information disclosure.
CVE-2009-1312
    It was discovered that Iceweasel allows Refresh: headers to redirect
    to Javascript URIs, resulting in cross-site scripting.
For the stable distribution (lenny), these problems have been fixed
in version 1.9.0.9-0lenny2.
As indicated in the Etch release notes, security support for the
Mozilla products in the oldstable distribution needed to be stopped
before the end of the regular Etch security maintenance life cycle.
You are strongly encouraged to upgrade to stable or switch to a still
supported browser.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1797');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xulrunner packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1797] DSA-1797-1 xulrunner");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1797-1 xulrunner");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmozillainterfaces-java', release: '5.0', reference: '1.9.0.9-0lenny2');
deb_check(prefix: 'libmozjs-dev', release: '5.0', reference: '1.9.0.9-0lenny2');
deb_check(prefix: 'libmozjs1d', release: '5.0', reference: '1.9.0.9-0lenny2');
deb_check(prefix: 'libmozjs1d-dbg', release: '5.0', reference: '1.9.0.9-0lenny2');
deb_check(prefix: 'python-xpcom', release: '5.0', reference: '1.9.0.9-0lenny2');
deb_check(prefix: 'spidermonkey-bin', release: '5.0', reference: '1.9.0.9-0lenny2');
deb_check(prefix: 'xulrunner-1.9', release: '5.0', reference: '1.9.0.9-0lenny2');
deb_check(prefix: 'xulrunner-1.9-dbg', release: '5.0', reference: '1.9.0.9-0lenny2');
deb_check(prefix: 'xulrunner-1.9-gnome-support', release: '5.0', reference: '1.9.0.9-0lenny2');
deb_check(prefix: 'xulrunner-dev', release: '5.0', reference: '1.9.0.9-0lenny2');
deb_check(prefix: 'xulrunner', release: '5.0', reference: '1.9.0.9-0lenny2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
