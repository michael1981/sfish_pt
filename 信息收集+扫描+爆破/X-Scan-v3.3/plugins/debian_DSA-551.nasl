# This script was automatically generated from the dsa-551
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15388);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "551");
 script_cve_id("CVE-2004-0794");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-551 security update');
 script_set_attribute(attribute: 'description', value:
'Przemyslaw Frasunek discovered a vulnerability in tnftpd or lukemftpd
respectively, the enhanced ftp daemon from NetBSD.  An attacker could
utilise this to execute arbitrary code on the server.
For the stable distribution (woody) this problem has been fixed in
version 1.1-1woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-551');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your lukemftpd package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA551] DSA-551-1 lukemftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-551-1 lukemftpd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'lukemftpd', release: '3.0', reference: '1.1-1woody2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
