# This script was automatically generated from the dsa-662
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16283);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "662");
 script_cve_id("CVE-2005-0104", "CVE-2005-0152");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-662 security update');
 script_set_attribute(attribute: 'description', value:
'Andrew Archibald discovered that the last update to squirrelmail which
was intended to fix several problems caused a regression which got
exposed when the user hits a session timeout.  For completeness below
is the original advisory text:
Several vulnerabilities have been discovered in Squirrelmail, a
commonly used webmail system.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    Upstream developers noticed that an unsanitised variable could
    lead to cross site scripting.
    Grant Hollingworth discovered that under certain circumstances URL
    manipulation could lead to the execution of arbitrary code with
    the privileges of www-data.  This problem only exists in version
    1.2.6 of Squirrelmail.
For the stable distribution (woody) these problems have been fixed in
version 1.2.6-3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-662');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your squirrelmail package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA662] DSA-662-2 squirrelmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-662-2 squirrelmail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'squirrelmail', release: '3.0', reference: '1.2.6-3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
