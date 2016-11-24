# This script was automatically generated from the dsa-759
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19221);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "759");
 script_cve_id("CVE-2005-2256");
 script_bugtraq_id(14142);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-759 security update');
 script_set_attribute(attribute: 'description', value:
'A vulnerability has been discovered in phppgadmin, a set of PHP
scripts to administrate PostgreSQL over the WWW, that can lead to
disclose sensitive information.  Successful exploitation requires that
"magic_quotes_gpc" is disabled.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 3.5.2-5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-759');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your phppgadmin package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA759] DSA-759-1 phppgadmin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-759-1 phppgadmin");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'phppgadmin', release: '3.1', reference: '3.5.2-5');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
