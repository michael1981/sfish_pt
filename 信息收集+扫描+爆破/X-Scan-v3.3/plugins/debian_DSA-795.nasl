# This script was automatically generated from the dsa-795
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19565);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "795");
 script_cve_id("CVE-2005-2390");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-795 security update');
 script_set_attribute(attribute: 'description', value:
'infamous42md reported that proftpd suffers from two format string
vulnerabilities. In the first, a user with the ability to create a
directory could trigger the format string error if there is a
proftpd shutdown message configured to use the "%C", "%R", or "%U"
variables. In the second, the error is triggered if mod_sql is used
to retrieve messages from a database and if format strings have been
inserted into the database by a user with permission to do so.
The old stable distribution (woody) is not affected by these
vulnerabilities.
For the stable distribution (sarge) this problem has been fixed in
version 1.2.10-15sarge1. There was an error in the packages originally
prepared for i386, which was corrected in 1.2.10-15sarge1.0.1 for i386.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-795');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your proftpd package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA795] DSA-795-2 proftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-795-2 proftpd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'proftpd', release: '3.1', reference: '1.2.10-15sarge1');
deb_check(prefix: 'proftpd-common', release: '3.1', reference: '1.2.10-15sarge1');
deb_check(prefix: 'proftpd-doc', release: '3.1', reference: '1.2.10-15sarge1');
deb_check(prefix: 'proftpd-ldap', release: '3.1', reference: '1.2.10-15sarge1');
deb_check(prefix: 'proftpd-mysql', release: '3.1', reference: '1.2.10-15sarge1');
deb_check(prefix: 'proftpd-pgsql', release: '3.1', reference: '1.2.10-15sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
