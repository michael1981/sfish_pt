# This script was automatically generated from the dsa-1607
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(33491);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1607");
 script_cve_id("CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2800", "CVE-2008-2801", "CVE-2008-2802", "CVE-2008-2803", "CVE-2008-2805");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1607 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the Iceweasel
webbrowser, an unbranded version of the Firefox browser. The Common 
Vulnerabilities and Exposures project identifies the following problems:
CVE-2008-2798
    Devon Hubbard, Jesse Ruderman and Martijn Wargers discovered
    crashes in the layout engine, which might allow the execution of
    arbitrary code.
CVE-2008-2799
    Igor Bukanov, Jesse Ruderman and Gary Kwong discovered crashes in
    the Javascript engine, which might allow the execution of arbitrary code.
CVE-2008-2800
    "moz_bug_r_a4" discovered several cross-site scripting vulnerabilities.
CVE-2008-2801
    Collin Jackson and Adam Barth discovered that Javascript code
    could be executed in the context of signed JAR archives.
CVE-2008-2802
    "moz_bug_r_a4" discovered that XUL documents can escalate
    privileges by accessing the pre-compiled "fastload" file.
CVE-2008-2803
    "moz_bug_r_a4" discovered that missing input sanitising in the
    mozIJSSubScriptLoader.loadSubScript() function could lead to the
    execution of arbitrary code. Iceweasel itself is not affected, but
    some addons are.
CVE-2008-2805
    Claudio Santambrogio discovered that missing access validation in
    DOM parsing allows malicious web sites to force the browser to
    upload local files to the server, which could lead to information
    disclosure.
CVE-2008-2807
    Daniel Glazman discovered that a programming error in the code for
    parsing .properties files could lead to memory content being
    exposed to addons, which could lead to information disclosure.
CVE-2008-2808
    Masahiro Yamada discovered that file URLS in directory listings
    were insufficiently escaped.
CVE-2008-2809
    John G. Myers, Frank Benkstein and Nils Toedtmann discovered that
    alternate names on self-signed certificates were handled
    insufficiently, which could lead to spoofings secure connections.
CVE-2008-2811
    Greg McManus discovered a crash in the block reflow
    code, which might allow the execution of arbitrary code.
For the stable distribution (etch), these problems have been fixed in
version 2.0.0.15-0etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1607');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your iceweasel package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1607] DSA-1607-1 iceweasel");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1607-1 iceweasel");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'firefox', release: '4.0', reference: '2.0.0.15-0etch1');
deb_check(prefix: 'firefox-dom-inspector', release: '4.0', reference: '2.0.0.15-0etch1');
deb_check(prefix: 'firefox-gnome-support', release: '4.0', reference: '2.0.0.15-0etch1');
deb_check(prefix: 'iceweasel', release: '4.0', reference: '2.0.0.15-0etch1');
deb_check(prefix: 'iceweasel-dbg', release: '4.0', reference: '2.0.0.15-0etch1');
deb_check(prefix: 'iceweasel-dom-inspector', release: '4.0', reference: '2.0.0.15-0etch1');
deb_check(prefix: 'iceweasel-gnome-support', release: '4.0', reference: '2.0.0.15-0etch1');
deb_check(prefix: 'mozilla-firefox', release: '4.0', reference: '2.0.0.15-0etch1');
deb_check(prefix: 'mozilla-firefox-dom-inspector', release: '4.0', reference: '2.0.0.15-0etch1');
deb_check(prefix: 'mozilla-firefox-gnome-support', release: '4.0', reference: '2.0.0.15-0etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
