# This script was automatically generated from the dsa-779
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19476);
 script_version("$Revision: 1.14 $");
 script_xref(name: "DSA", value: "779");
 script_bugtraq_id(14242);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-779 security update');
 script_set_attribute(attribute: 'description', value:
'We experienced that the update for Mozilla Firefox from DSA 779-1
unfortunately was a regression in several cases.  Since the usual
praxis of backporting apparently does not work, this update is
basically version 1.0.6 with the version number rolled back, and hence
still named 1.0.4-*.  For completeness below is the original advisory
text:
Several problems have been discovered in Mozilla Firefox, a
lightweight web browser based on Mozilla.  The Common Vulnerabilities
and Exposures project identifies the following problems:
    The browser user interface does not properly distinguish between
    user-generated events and untrusted synthetic events, which makes
    it easier for remote attackers to perform dangerous actions that
    normally could only be performed manually by the user.
    XML scripts ran even when Javascript disabled.
    The user can be tricked to executing arbitrary JavaScript code by
    using a JavaScript URL as wallpaper.
    It is possible for a remote attacker to execute a callback
    function in the context of another domain (i.e. frame).
    By opening a malicious link in the sidebar it is possible for
    remote attackers to steal sensitive information.
    Missing input sanitising of InstallVersion.compareTo() can cause
    the application to crash.
    Remote attackers could steal sensitive information such as cookies
    and passwords from web sites by accessing data in alien frames.
    By using standalone applications such as Flash and QuickTime to
    open a javascript: URL, it is possible for a remote attacker to
    steal sensitive information and possibly execute arbitrary code.
    It is possible for a Javascript dialog box to spoof a dialog box
    from a trusted site and facilitates phishing attacks.
    Remote attackers could modify certain tag properties of DOM nodes
    that could lead to the execution of arbitrary script or code.
    The Mozilla browser family does not properly clone base objects,
    which allows remote attackers to execute arbitrary code.
The old stable distribution (woody) is not affected by these problems.
For the stable distribution (sarge) these problems have been fixed in
version 1.0.4-2sarge3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-779');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your Mozilla Firefox packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA779] DSA-779-2 mozilla-firefox");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_cve_id("CVE-2005-2260", "CVE-2005-2261", "CVE-2005-2262", "CVE-2005-2263", "CVE-2005-2264", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2267", "CVE-2005-2268", "CVE-2005-2269", "CVE-2005-2270");
 script_summary(english: "DSA-779-2 mozilla-firefox");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mozilla-firefox', release: '3.1', reference: '1.0.4-2sarge3');
deb_check(prefix: 'mozilla-firefox-dom-inspector', release: '3.1', reference: '1.0.4-2sarge3');
deb_check(prefix: 'mozilla-firefox-gnome-support', release: '3.1', reference: '1.0.4-2sarge3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
