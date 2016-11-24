# This script was automatically generated from the dsa-173
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15010);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "173");
 script_cve_id("CVE-2002-1196");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-173 security update');
 script_set_attribute(attribute: 'description', value:
'The developers of Bugzilla, a web-based bug tracking system,
discovered a problem in the handling of more than 47 groups.  When a
new product is added to an installation with 47 groups or more and
"usebuggroups" is enabled, the new group will be assigned a groupset
bit using Perl math that is not exact beyond 248.
This results in
the new group being defined with a "bit" that has several bits set.
As users are given access to the new group, those users will also gain
access to spurious lower group privileges.  Also, group bits were not
always reused when groups were deleted.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-173');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your bugzilla package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA173] DSA-173-1 bugzilla");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-173-1 bugzilla");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'bugzilla', release: '3.0', reference: '2.14.2-0woody2');
deb_check(prefix: 'bugzilla-doc', release: '3.0', reference: '2.14.2-0woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
