# This script was automatically generated from the dsa-732
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18519);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "732");
 script_cve_id("CVE-2005-1520", "CVE-2005-1521", "CVE-2005-1522", "CVE-2005-1523");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-732 security update');
 script_set_attribute(attribute: 'description', value:
'"infamous41md" discovered several vulnerabilities in the GNU mailutils
package which contains utilities for handling mail.  These problems
can lead to a denial of service or the execution of arbitrary code.
The Common Vulnerabilities and Exposures project identifies the
following vulnerabilities.
    Buffer overflow mail header handling may allow a remote attacker
    to execute commands with the privileges of the targeted user.
    Combined integer and heap overflow in the fetch routine can lead
    to the execution of arbitrary code.
    Denial of service in the fetch routine.
    Format string vulnerability can lead to the execution of arbitrary
    code.
For the stable distribution (woody) these problems have been fixed in
version 20020409-1woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-732');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mailutils packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA732] DSA-732-1 mailutils");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-732-1 mailutils");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmailutils0', release: '3.0', reference: '20020409-1woody2');
deb_check(prefix: 'libmailutils0-dev', release: '3.0', reference: '20020409-1woody2');
deb_check(prefix: 'mailutils', release: '3.0', reference: '20020409-1woody2');
deb_check(prefix: 'mailutils-doc', release: '3.0', reference: '20020409-1woody2');
deb_check(prefix: 'mailutils-imap4d', release: '3.0', reference: '20020409-1woody2');
deb_check(prefix: 'mailutils-pop3d', release: '3.0', reference: '20020409-1woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
