# This script was automatically generated from the dsa-1175
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22717);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1175");
 script_cve_id("CVE-2006-4436");
 script_bugtraq_id(19712);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1175 security update');
 script_set_attribute(attribute: 'description', value:
'A flaw has been found in isakmpd, OpenBSD\'s implementation of the
Internet Key Exchange protocol, that caused Security Associations to be
created with a replay window of 0 when isakmpd was acting as the
responder during SA negotiation.  This could allow an attacker to
re-inject sniffed IPsec packets, which would not be checked against the
replay counter.
For the stable distribution (sarge) this problem has been fixed in
version 20041012-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1175');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your isakmpd package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1175] DSA-1175-1 isakmpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1175-1 isakmpd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'isakmpd', release: '3.1', reference: '20041012-1sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
