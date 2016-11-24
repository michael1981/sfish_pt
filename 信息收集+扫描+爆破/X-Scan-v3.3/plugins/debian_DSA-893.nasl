# This script was automatically generated from the dsa-893
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22759);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "893");
 script_cve_id("CVE-2005-3325");
 script_bugtraq_id(15199);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-893 security update');
 script_set_attribute(attribute: 'description', value:
'Remco Verhoef has discovered a vulnerability in acidlab, Analysis
Console for Intrusion Databases, and in acidbase, Basic Analysis and
Security Engine, which can be exploited by malicious users to conduct
SQL injection attacks.
The maintainers of Analysis Console for Intrusion Databases (ACID) in Debian,
of which BASE is a fork off, after a security audit of both BASE and ACID
have determined that the flaw found not only affected the base_qry_main.php (in
BASE) or acid_qry_main.php (in ACID) component but was also found in other
elements of the consoles due to improper parameter validation and filtering.
All the SQL injection bugs and Cross Site Scripting bugs found have been
fixed in the Debian package, closing all the different attack vectors detected.
For the old stable distribution (woody) this problem has been fixed in
version 0.9.6b20-2.1.
For the stable distribution (sarge) this problem has been fixed in
version 0.9.6b20-10.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-893');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your acidlab and acidbase package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA893] DSA-893-1 acidlab");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-893-1 acidlab");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'acidlab', release: '3.0', reference: '0.9.6b20-2.1');
deb_check(prefix: 'acidlab', release: '3.1', reference: '0.9.6b20-10.1');
deb_check(prefix: 'acidlab-doc', release: '3.1', reference: '0.9.6b20-10.1');
deb_check(prefix: 'acidlab-mysql', release: '3.1', reference: '0.9.6b20-10.1');
deb_check(prefix: 'acidlab-pgsql', release: '3.1', reference: '0.9.6b20-10.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
