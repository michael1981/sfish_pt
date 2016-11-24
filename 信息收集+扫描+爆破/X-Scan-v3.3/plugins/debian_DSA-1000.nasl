# This script was automatically generated from the dsa-1000
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22542);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1000");
 script_cve_id("CVE-2006-0042");
 script_bugtraq_id(16710);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1000 security update');
 script_set_attribute(attribute: 'description', value:
'Gunnar Wolf noticed that the correction for the following problem was
not complete and requires an update.  For completeness we\'re
providing the original problem description:
An algorithm weakness has been discovered in Apache2::Request, the
generic request library for Apache2 which can be exploited remotely
and cause a denial of service via CPU consumption.
The old stable distribution (woody) does not contain this package.
For the stable distribution (sarge) this problem has been fixed in
version 2.04-dev-1sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1000');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libapreq2, libapache2-mod-apreq2
and libapache2-request-perl packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1000] DSA-1000-2 libapreq2-perl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1000-2 libapreq2-perl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libapache2-request-perl', release: '3.1', reference: '2.04-dev-1sarge2');
deb_check(prefix: 'libapreq2-perl', release: '3.1', reference: '2.04-dev-1sarge2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
