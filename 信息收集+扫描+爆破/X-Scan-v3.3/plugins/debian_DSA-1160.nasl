# This script was automatically generated from the dsa-1160
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22702);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1160");
 script_cve_id("CVE-2006-2779", "CVE-2006-3805", "CVE-2006-3806", "CVE-2006-3807", "CVE-2006-3808", "CVE-2006-3809", "CVE-2006-3810");
 script_bugtraq_id(18228, 19181);
 script_xref(name: "CERT", value: "466673");
 script_xref(name: "CERT", value: "655892");
 script_xref(name: "CERT", value: "687396");
 script_xref(name: "CERT", value: "876420");
 script_xref(name: "CERT", value: "911004");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1160 security update');
 script_set_attribute(attribute: 'description', value:
'The latest security updates of Mozilla introduced a regression that
led to a dysfunctional attachment panel which warrants a correction to
fix this issue. For reference please find below the original advisory
text:
Several security related problems have been discovered in Mozilla and
derived products.  The Common Vulnerabilities and Exposures project
identifies the following vulnerabilities:
CVE-2006-2779
    Mozilla team members discovered several crashes during testing of
    the browser engine showing evidence of memory corruption which may
    also lead to the execution of arbitrary code.  The last bit of
    this problem will be corrected with the next update.  You can
    prevent any trouble by disabling Javascript.  [MFSA-2006-32]
CVE-2006-3805
    The Javascript engine might allow remote attackers to execute
    arbitrary code.  [MFSA-2006-50]
CVE-2006-3806
    Multiple integer overflows in the Javascript engine might allow
    remote attackers to execute arbitrary code.  [MFSA-2006-50]
CVE-2006-3807
    Specially crafted Javascript allows remote attackers to execute
    arbitrary code.  [MFSA-2006-51]
CVE-2006-3808
    Remote Proxy AutoConfig (PAC) servers could execute code with elevated
    privileges via a specially crafted PAC script.  [MFSA-2006-52]
CVE-2006-3809
    Scripts with the UniversalBrowserRead privilege could gain
    UniversalXPConnect privileges and possibly execute code or obtain
    sensitive data.  [MFSA-2006-53]
CVE-2006-3810
    A cross-site scripting vulnerability allows remote attackers to
    inject arbitrary web script or HTML.  [MFSA-2006-54]
For the stable distribution (sarge) these problems have been fixed in
version 1.7.8-1sarge7.2.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1160');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mozilla package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1160] DSA-1160-2 mozilla");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1160-2 mozilla");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libnspr-dev', release: '3.1', reference: '1.7.8-1sarge7.2.2');
deb_check(prefix: 'libnspr4', release: '3.1', reference: '1.7.8-1sarge7.2.2');
deb_check(prefix: 'libnss-dev', release: '3.1', reference: '1.7.8-1sarge7.2.2');
deb_check(prefix: 'libnss3', release: '3.1', reference: '1.7.8-1sarge7.2.2');
deb_check(prefix: 'mozilla', release: '3.1', reference: '1.7.8-1sarge7.2.2');
deb_check(prefix: 'mozilla-browser', release: '3.1', reference: '1.7.8-1sarge7.2.2');
deb_check(prefix: 'mozilla-calendar', release: '3.1', reference: '1.7.8-1sarge7.2.2');
deb_check(prefix: 'mozilla-chatzilla', release: '3.1', reference: '1.7.8-1sarge7.2.2');
deb_check(prefix: 'mozilla-dev', release: '3.1', reference: '1.7.8-1sarge7.2.2');
deb_check(prefix: 'mozilla-dom-inspector', release: '3.1', reference: '1.7.8-1sarge7.2.2');
deb_check(prefix: 'mozilla-js-debugger', release: '3.1', reference: '1.7.8-1sarge7.2.2');
deb_check(prefix: 'mozilla-mailnews', release: '3.1', reference: '1.7.8-1sarge7.2.2');
deb_check(prefix: 'mozilla-psm', release: '3.1', reference: '1.7.8-1sarge7.2.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
