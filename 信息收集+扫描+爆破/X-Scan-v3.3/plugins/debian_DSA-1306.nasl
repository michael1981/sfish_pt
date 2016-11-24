# This script was automatically generated from the dsa-1306
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25505);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "1306");
 script_cve_id("CVE-2007-1362", "CVE-2007-2867", "CVE-2007-2868", "CVE-2007-2869", "CVE-2007-2870", "CVE-2007-2871");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1306 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in Xulrunner, a
runtime environment for XUL applications. The Common Vulnerabilities
and Exposures project identifies the following problems:
CVE-2007-1362
    Nicolas Derouet discovered that Xulrunner performs insufficient
    validation of cookies, which could lead to denial of service.
CVE-2007-2867
    Boris Zbarsky, Eli Friedman, Georgi Guninski, Jesse Ruderman, Martijn
    Wargers and Olli Pettay discovered crashes in the layout engine, which
    might allow the execution of arbitrary code.
CVE-2007-2868
    Brendan Eich, Igor Bukanov, Jesse Ruderman, <q>moz_bug_r_a4</q> and Wladimir
    Palant discovered crashes in the Javascript engine, which might allow
    the execution of arbitrary code.
CVE-2007-2869
    <q>Marcel</q> discovered that malicous web sites can cause massive
    resource consumption through the auto completion feature, resulting
    in denial of service.
CVE-2007-2870
    <q>moz_bug_r_a4</q> discovered that adding an event listener through the
     addEventListener() function allows cross-site scripting.
CVE-2007-2871
     Chris Thomas discovered that XUL popups can be abused for spoofing
     or phishing attacks.
The oldstable distribution (sarge) doesn\'t include xulrunner.
For the stable distribution (etch) these problems have been fixed in
version 1.8.0.12-0etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1306');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xulrunner packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1306] DSA-1306-1 xulrunner");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1306-1 xulrunner");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmozillainterfaces-java', release: '4.0', reference: '1.8.0.12-0etch1');
deb_check(prefix: 'libmozjs-dev', release: '4.0', reference: '1.8.0.12-0etch1');
deb_check(prefix: 'libmozjs0d', release: '4.0', reference: '1.8.0.12-0etch1');
deb_check(prefix: 'libmozjs0d-dbg', release: '4.0', reference: '1.8.0.12-0etch1');
deb_check(prefix: 'libnspr4-0d', release: '4.0', reference: '1.8.0.12-0etch1');
deb_check(prefix: 'libnspr4-0d-dbg', release: '4.0', reference: '1.8.0.12-0etch1');
deb_check(prefix: 'libnspr4-dev', release: '4.0', reference: '1.8.0.12-0etch1');
deb_check(prefix: 'libnss3-0d', release: '4.0', reference: '1.8.0.12-0etch1');
deb_check(prefix: 'libnss3-0d-dbg', release: '4.0', reference: '1.8.0.12-0etch1');
deb_check(prefix: 'libnss3-dev', release: '4.0', reference: '1.8.0.12-0etch1');
deb_check(prefix: 'libnss3-tools', release: '4.0', reference: '1.8.0.12-0etch1');
deb_check(prefix: 'libsmjs-dev', release: '4.0', reference: '1.8.0.12-0etch1');
deb_check(prefix: 'libsmjs1', release: '4.0', reference: '1.8.0.12-0etch1');
deb_check(prefix: 'libxul-common', release: '4.0', reference: '1.8.0.12-0etch1');
deb_check(prefix: 'libxul-dev', release: '4.0', reference: '1.8.0.12-0etch1');
deb_check(prefix: 'libxul0d', release: '4.0', reference: '1.8.0.12-0etch1');
deb_check(prefix: 'libxul0d-dbg', release: '4.0', reference: '1.8.0.12-0etch1');
deb_check(prefix: 'python-xpcom', release: '4.0', reference: '1.8.0.12-0etch1');
deb_check(prefix: 'spidermonkey-bin', release: '4.0', reference: '1.8.0.12-0etch1');
deb_check(prefix: 'xulrunner', release: '4.0', reference: '1.8.0.12-0etch1');
deb_check(prefix: 'xulrunner-gnome-support', release: '4.0', reference: '1.8.0.12-0etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
