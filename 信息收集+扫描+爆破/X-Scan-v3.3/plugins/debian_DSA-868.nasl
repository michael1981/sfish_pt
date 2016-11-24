# This script was automatically generated from the dsa-868
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(20071);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "868");
 script_bugtraq_id(14784);
 script_xref(name: "CERT", value: "573857");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-868 security update');
 script_set_attribute(attribute: 'description', value:
'Several security-related problems have been discovered in Mozilla and
derived programs.  Some of the following problems don\'t exactly apply
to Mozilla Thunderbird, even though the code is present.  In order to
keep the codebase in sync with upstream it has been altered
nevertheless.  The Common Vulnerabilities and Exposures project
identifies the following problems:
    Tom Ferris discovered a bug in the IDN hostname handling of
    Mozilla that allows remote attackers to cause a denial of service
    and possibly execute arbitrary code via a hostname with dashes.
    A buffer overflow allows remote attackers to execute arbitrary
    code via an XBM image file that ends in a large number of spaces
    instead of the expected end tag.
    Mats Palmgren discovered a buffer overflow in the Unicode string
    parser that allows a specially crafted Unicode sequence to
    overflow a buffer and cause arbitrary code to be executed.
    Remote attackers could spoof HTTP headers of XML HTTP requests
    via XMLHttpRequest and possibly use the client to exploit
    vulnerabilities in servers or proxies.
    Remote attackers could spoof DOM objects via an XBL control that
    implements an internal XPCOM interface.
    Georgi Guninski discovered an integer overflow in the JavaScript
    engine that might allow remote attackers to execute arbitrary
    code.
    Remote attackers could execute Javascript code with chrome
    privileges via an about: page such as about:mozilla.
    Remote attackers could spawn windows without user interface
    components such as the address and status bar that could be used
    to conduct spoofing or phishing attacks.
    Peter Zelezny discovered that shell metacharacters are not
    properly escaped when they are passed to a shell script and allow
    the execution of arbitrary commands, e.g. when a malicious URL is
    automatically copied from another program into Mozilla as default
    browser.
For the stable distribution (sarge) these problems have been fixed in
version 1.0.2-2.sarge1.0.7.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-868');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mozilla-thunderbird package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA868] DSA-868-1 mozilla-thunderbird");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_cve_id("CVE-2005-2701", "CVE-2005-2702", "CVE-2005-2703", "CVE-2005-2704", "CVE-2005-2705", "CVE-2005-2706", "CVE-2005-2707", "CVE-2005-2871");
 script_summary(english: "DSA-868-1 mozilla-thunderbird");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mozilla-thunderbird', release: '3.1', reference: '1.0.2-2.sarge1.0.7');
deb_check(prefix: 'mozilla-thunderbird-dev', release: '3.1', reference: '1.0.2-2.sarge1.0.7');
deb_check(prefix: 'mozilla-thunderbird-inspector', release: '3.1', reference: '1.0.2-2.sarge1.0.7');
deb_check(prefix: 'mozilla-thunderbird-offline', release: '3.1', reference: '1.0.2-2.sarge1.0.7');
deb_check(prefix: 'mozilla-thunderbird-typeaheadfind', release: '3.1', reference: '1.0.2-2.sarge1.0.7');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
