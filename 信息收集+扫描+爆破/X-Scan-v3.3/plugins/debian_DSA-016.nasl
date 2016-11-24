# This script was automatically generated from the dsa-016
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14853);
 script_version("$Revision: 1.13 $");
 script_xref(name: "DSA", value: "016");
 script_bugtraq_id(2189);
 script_bugtraq_id(2296);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-016 security update');
 script_set_attribute(attribute: 'description', value:
'Security people at WireX have noticed a temp file creation
bug and the WU-FTPD development team has found a possible format string bug in
wu-ftpd. Both could be remotely exploited, though no such exploit exists
currently.

We recommend you upgrade your wu-ftpd package immediately.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-016');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-016
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA016] DSA-016-3 wu-ftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_cve_id("CVE-2001-0138", "CVE-2001-0187");
 script_summary(english: "DSA-016-3 wu-ftpd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'wu-ftpd', release: '2.2', reference: '2.6.0-5.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
