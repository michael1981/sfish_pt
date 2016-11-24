# This script was automatically generated from the dsa-1155
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22697);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1155");
 script_cve_id("CVE-2006-1173");
 script_bugtraq_id(18433);
 script_xref(name: "CERT", value: "146718");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1155 security update');
 script_set_attribute(attribute: 'description', value:
'It turned out that the sendmail binary depends on libsasl2 (>= 2.1.19.dfsg1)
which is neither available in the stable nor in the security archive.
This version is scheduled for the inclusion in the next update of the
stable release, though.
You\'ll have to download the referenced file for your architecture from
below and install it with dpkg -i.
As an alternative, temporarily adding the following line to
/etc/apt/sources.list will mitigate the problem as well:
Here is the original security advisory for completeness:
Frank Sheiness discovered that a MIME conversion routine in sendmail,
a powerful, efficient, and scalable mail transport agent, could be
tricked by a specially crafted mail to perform an endless recursion.
For the stable distribution (sarge) this problem has been fixed in
version 8.13.4-3sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1155');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your sendmail package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1155] DSA-1155-2 sendmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1155-2 sendmail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmilter-dev', release: '3.1', reference: '8.13.4-3sarge2');
deb_check(prefix: 'libmilter0', release: '3.1', reference: '8.13.4-3sarge2');
deb_check(prefix: 'libsasl2', release: '3.1', reference: '2.1.19.dfsg1-0sarge2');
deb_check(prefix: 'rmail', release: '3.1', reference: '8.13.4-3sarge2');
deb_check(prefix: 'sendmail', release: '3.1', reference: '8.13.4-3sarge2');
deb_check(prefix: 'sendmail-base', release: '3.1', reference: '8.13.4-3sarge2');
deb_check(prefix: 'sendmail-bin', release: '3.1', reference: '8.13.4-3sarge2');
deb_check(prefix: 'sendmail-cf', release: '3.1', reference: '8.13.4-3sarge2');
deb_check(prefix: 'sendmail-doc', release: '3.1', reference: '8.13.4-3sarge2');
deb_check(prefix: 'sensible-mda', release: '3.1', reference: '8.13.4-3sarge2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
