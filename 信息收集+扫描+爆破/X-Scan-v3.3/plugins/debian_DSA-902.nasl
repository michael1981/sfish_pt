# This script was automatically generated from the dsa-902
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22768);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "902");
 script_cve_id("CVE-2005-2943");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-902 security update');
 script_set_attribute(attribute: 'description', value:
'A buffer overflow has been discovered in the sendmail program of
xmail, an advanced, fast and reliable ESMTP/POP3 mail server that
could lead to the execution of arbitrary code with group mail
privileges.
The old stable distribution (woody) does not contain xmail packages.
For the stable distribution (sarge) this problem has been fixed in
version 1.21-3sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-902');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xmail package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA902] DSA-902-1 xmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-902-1 xmail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xmail', release: '3.1', reference: '1.21-3sarge1');
deb_check(prefix: 'xmail-doc', release: '3.1', reference: '1.21-3sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
