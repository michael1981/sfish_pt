# This script was automatically generated from the dsa-848
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19956);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "848");
 script_cve_id("CVE-2005-2662", "CVE-2005-2663");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-848 security update');
 script_set_attribute(attribute: 'description', value:
'Jens Steube discovered two vulnerabilities in masqmail, a mailer for
hosts without permanent internet connection.  The Common
Vulnerabilities and Exposures project identifies the following
problems:
    When sending failed mail messages, the address is not sanitised,
    which allows a local attacker to execute arbitrary commands as the
    mail user.
    When opening the log file, masqmail does not relinquish
    privileges, which allows a local attacker to overwrite arbitrary
    files via a symlink attack.
For the old stable distribution (woody) these problems have been fixed in
version 0.1.16-2.2.
For the stable distribution (sarge) these problems have been fixed in
version 0.2.20-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-848');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your masqmail package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA848] DSA-848-1 masqmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-848-1 masqmail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'masqmail', release: '3.0', reference: '0.1.16-2.2');
deb_check(prefix: 'masqmail', release: '3.1', reference: '0.2.20-1sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
