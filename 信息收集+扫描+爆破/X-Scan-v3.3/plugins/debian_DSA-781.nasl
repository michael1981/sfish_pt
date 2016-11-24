# This script was automatically generated from the dsa-781
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19478);
 script_version("$Revision: 1.13 $");
 script_xref(name: "DSA", value: "781");
 script_bugtraq_id(14242);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-781 security update');
 script_set_attribute(attribute: 'description', value:
'Several problems have been discovered in Mozilla Thunderbird, the
standalone mail client of the Mozilla suite.  The Common
Vulnerabilities and Exposures project identifies the following
problems:
    Remote attackers could read portions of heap memory into a
    Javascript string via the lambda replace method.
    The Javascript interpreter could be tricked to continue execution
    at the wrong memory address, which may allow attackers to cause a
    denial of service (application crash) and possibly execute
    arbitrary code.
    Remote attackers could override certain properties or methods of
    DOM nodes and gain privileges.
    Remote attackers could override certain properties or methods due
    to missing proper limitation of Javascript eval and Script objects
    and gain privileges.
    XML scripts ran even when Javascript disabled.
    Missing input sanitising of InstallVersion.compareTo() can cause
    the application to crash.
    Remote attackers could steal sensitive information such as cookies
    and passwords from web sites by accessing data in alien frames.
    Remote attackers could modify certain tag properties of DOM nodes
    that could lead to the execution of arbitrary script or code.
    The Mozilla browser family does not properly clone base objects,
    which allows remote attackers to execute arbitrary code.
The old stable distribution (woody) is not affected by these problems
since it does not contain Mozilla Thunderbird packages.
For the stable distribution (sarge) these problems have been fixed in
version 1.0.2-2.sarge1.0.6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-781');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your Mozilla Thunderbird package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA781] DSA-781-1 mozilla-thunderbird");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_cve_id("CVE-2005-0989", "CVE-2005-1159", "CVE-2005-1160", "CVE-2005-1532", "CVE-2005-2261", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2269", "CVE-2005-2270");
 script_summary(english: "DSA-781-1 mozilla-thunderbird");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mozilla-thunderbird', release: '3.1', reference: '1.0.2-2.sarge1.0.6');
deb_check(prefix: 'mozilla-thunderbird-dev', release: '3.1', reference: '1.0.2-2.sarge1.0.6');
deb_check(prefix: 'mozilla-thunderbird-inspector', release: '3.1', reference: '1.0.2-2.sarge1.0.6');
deb_check(prefix: 'mozilla-thunderbird-offline', release: '3.1', reference: '1.0.2-2.sarge1.0.6');
deb_check(prefix: 'mozilla-thunderbird-typeaheadfind', release: '3.1', reference: '1.0.2-2.sarge1.0.6');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
