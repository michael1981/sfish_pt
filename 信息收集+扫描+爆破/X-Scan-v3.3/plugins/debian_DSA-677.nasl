# This script was automatically generated from the dsa-677
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16381);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "677");
 script_cve_id("CVE-2005-0073");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-677 security update');
 script_set_attribute(attribute: 'description', value:
'Erik Sjölund discovered that a support script of sympa, a mailing list
manager, is running setuid sympa and vulnerable to a buffer overflow.
This could potentially lead to the execution of arbitrary code under
the sympa user id.
For the stable distribution (woody) this problem has been fixed in
version 3.3.3-3woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-677');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your sympa package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA677] DSA-677-1 sympa");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-677-1 sympa");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'sympa', release: '3.0', reference: '3.3.3-3woody2');
deb_check(prefix: 'wwsympa', release: '3.0', reference: '3.3.3-3woody2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
