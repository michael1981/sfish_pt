# This script was automatically generated from the dsa-161
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14998);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "161");
 script_cve_id("CVE-2002-1115", "CVE-2002-1116");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-161 security update');
 script_set_attribute(attribute: 'description', value:
'A problem with user privileges has been discovered in the Mantis
package, a PHP based bug tracking system.  The Mantis system didn\'t
check whether a user is permitted to view a bug, but displays it right
away if the user entered a valid bug id.
Another bug in Mantis caused the \'View Bugs\' page to list bugs from
both public and private projects when no projects are accessible to
the current user.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-161');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mantis packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA161] DSA-161-1 mantis");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-161-1 mantis");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mantis', release: '3.0', reference: '0.17.1-2.5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
