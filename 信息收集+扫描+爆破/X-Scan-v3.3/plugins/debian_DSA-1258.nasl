# This script was automatically generated from the dsa-1258
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(24297);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1258");
 script_cve_id("CVE-2006-6497", "CVE-2006-6498", "CVE-2006-6499", "CVE-2006-6501", "CVE-2006-6502", "CVE-2006-6503");
 script_bugtraq_id(21668);
 script_xref(name: "CERT", value: "263412");
 script_xref(name: "CERT", value: "405092");
 script_xref(name: "CERT", value: "427972");
 script_xref(name: "CERT", value: "428500");
 script_xref(name: "CERT", value: "447772");
 script_xref(name: "CERT", value: "606260");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1258 security update');
 script_set_attribute(attribute: 'description', value:
'Several security related problems have been discovered in Mozilla and
derived products such as Mozilla Firefox.  The Common Vulnerabilities
and Exposures project identifies the following vulnerabilities:
CVE-2006-6497
    Several vulnerabilities in the layout engine allow remote
    attackers to cause a denial of service and possibly permit them to
    execute arbitrary code. [MFSA 2006-68]
CVE-2006-6498
    Several vulnerabilities in the JavaScript engine allow remote
    attackers to cause a denial of service and possibly permit them to
    execute arbitrary code. [MFSA 2006-68]
CVE-2006-6499
    A bug in the js_dtoa function allows remote attackers to cause a
    denial of service. [MFSA 2006-68]
CVE-2006-6501
    "shutdown" discovered a vulnerability that allows remote attackers
    to gain privileges and install malicious code via the watch
    JavaScript function. [MFSA 2006-70]
CVE-2006-6502
    Steven Michaud discovered a programming bug that allows remote
    attackers to cause a denial of service. [MFSA 2006-71]
CVE-2006-6503
    "moz_bug_r_a4" reported that the src attribute of an IMG element
    could be used to inject JavaScript code. [MFSA 2006-72]
For the stable distribution (sarge) these problems have been fixed in
version 1.0.2-2.sarge1.0.8e.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1258');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your Mozilla Thunderbird and Icedove packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1258] DSA-1258-1 mozilla-thunderbird");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1258-1 mozilla-thunderbird");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mozilla-thunderbird', release: '3.1', reference: '1.0.2-2.sarge1.0.8e.2');
deb_check(prefix: 'mozilla-thunderbird-dev', release: '3.1', reference: '1.0.2-2.sarge1.0.8e.2');
deb_check(prefix: 'mozilla-thunderbird-inspector', release: '3.1', reference: '1.0.2-2.sarge1.0.8e.2');
deb_check(prefix: 'mozilla-thunderbird-offline', release: '3.1', reference: '1.0.2-2.sarge1.0.8e.2');
deb_check(prefix: 'mozilla-thunderbird-typeaheadfind', release: '3.1', reference: '1.0.2-2.sarge1.0.8e.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
