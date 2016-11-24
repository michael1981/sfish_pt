# This script was automatically generated from the dsa-154
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14991);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "154");
 script_cve_id("CVE-2002-0875");
 script_bugtraq_id(5487);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-154 security update');
 script_set_attribute(attribute: 'description', value:
'A flaw
was discovered in FAM\'s group handling.  In the effect users
are unable to read FAM directories they have group read and execute
permissions on.  However, also unprivileged users can potentially
learn names of files that only users in root\'s group should be able to
view.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-154');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your fam packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA154] DSA-154-1 fam");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-154-1 fam");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'fam', release: '3.0', reference: '2.6.6.1-5.2');
deb_check(prefix: 'libfam-dev', release: '3.0', reference: '2.6.6.1-5.2');
deb_check(prefix: 'libfam0', release: '3.0', reference: '2.6.6.1-5.2');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
