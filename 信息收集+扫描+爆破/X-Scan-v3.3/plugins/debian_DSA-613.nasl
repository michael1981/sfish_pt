# This script was automatically generated from the dsa-613
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16013);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "613");
 script_cve_id("CVE-2004-1142");
 script_bugtraq_id(11943);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-613 security update');
 script_set_attribute(attribute: 'description', value:
'Brian Caswell discovered that an improperly formatted SMB packet could
make ethereal hang and eat CPU endlessly.
For the stable distribution (woody) this problem has been fixed in
version 0.9.4-1woody9.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-613');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ethereal packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA613] DSA-613-1 ethereal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-613-1 ethereal");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ethereal', release: '3.0', reference: '0.9.4-1woody9');
deb_check(prefix: 'ethereal-common', release: '3.0', reference: '0.9.4-1woody9');
deb_check(prefix: 'ethereal-dev', release: '3.0', reference: '0.9.4-1woody9');
deb_check(prefix: 'tethereal', release: '3.0', reference: '0.9.4-1woody9');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
