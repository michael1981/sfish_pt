# This script was automatically generated from the dsa-1659
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(34492);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1659");
 script_cve_id("CVE-2008-2469");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1659 security update');
 script_set_attribute(attribute: 'description', value:
'Dan Kaminsky discovered that libspf2, an implementation of the Sender
Policy Framework (SPF) used by mail servers for mail filtering, handles
malformed TXT records incorrectly, leading to a buffer overflow
condition (CVE-2008-2469).
Note that the SPF configuration template in Debian\'s Exim configuration
recommends to use libmail-spf-query-perl, which does not suffer from
this issue.
For the stable distribution (etch), this problem has been fixed in
version 1.2.5-4+etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1659');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libspf2 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1659] DSA-1659-1 libspf2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1659-1 libspf2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libspf2-2', release: '4.0', reference: '1.2.5-4+etch1');
deb_check(prefix: 'libspf2-dev', release: '4.0', reference: '1.2.5-4+etch1');
deb_check(prefix: 'spfquery', release: '4.0', reference: '1.2.5-4+etch1');
deb_check(prefix: 'libspf2', release: '4.0', reference: '1.2.5-4+etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
