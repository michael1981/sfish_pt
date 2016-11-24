# This script was automatically generated from the dsa-1640
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(34253);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1640");
 script_cve_id("CVE-2007-5712", "CVE-2008-3909");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1640 security update');
 script_set_attribute(attribute: 'description', value:
'Simon Willison discovered that in Django, a Python web framework, the
feature to retain HTTP POST data during user reauthentication allowed
a remote attacker to perform unauthorized modification of data through
cross site request forgery. This is possible regardless of the Django
plugin to prevent cross site request forgery being enabled. The Common
Vulnerabilities and Exposures project identifies this issue as
CVE-2008-3909.
In this update the affected feature is disabled; this is in accordance
with upstream\'s preferred solution for this situation.
This update takes the opportunity to also include a relatively minor
denial of service attack in the internationalisation framework, known
as CVE-2007-5712.
For the stable distribution (etch), these problems have been fixed in
version 0.95.1-1etch2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1640');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your python-django package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1640] DSA-1640-1 python-django");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1640-1 python-django");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'python-django', release: '4.0', reference: '0.95.1-1etch2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
