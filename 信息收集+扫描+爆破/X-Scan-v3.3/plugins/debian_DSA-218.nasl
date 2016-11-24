# This script was automatically generated from the dsa-218
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15055);
 script_version("$Revision: 1.13 $");
 script_xref(name: "DSA", value: "218");
 script_bugtraq_id(6257);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-218 security update');
 script_set_attribute(attribute: 'description', value:
'A cross site scripting vulnerability has been reported for Bugzilla, a
web-based bug tracking system.  Bugzilla does not properly sanitize
any input submitted by users for use in quips.  As a result, it is possible for a
remote attacker to create a malicious link containing script code
which will be executed in the browser of a legitimate user, in the
context of the website running Bugzilla.  This issue may be exploited
to steal cookie-based authentication credentials from legitimate users
of the website running the vulnerable software.
This vulnerability only affects users who have the \'quips\' feature
enabled and who upgraded from version 2.10 which did not exist inside
of Debian.  The Debian package history of Bugzilla starts with 1.13
and jumped to 2.13.  However, users could have installed version 2.10
prior to the Debian package.
For the current stable distribution (woody) this problem has been
fixed in version 2.14.2-0woody3.
The old stable distribution (potato) does not contain a Bugzilla
package.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-218');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your bugzilla packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA218] DSA-218-1 bugzilla");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_cve_id("CVE-2002-2260");
 script_summary(english: "DSA-218-1 bugzilla");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'bugzilla', release: '3.0', reference: '2.14.2-0woody3');
deb_check(prefix: 'bugzilla-doc', release: '3.0', reference: '2.14.2-0woody3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
