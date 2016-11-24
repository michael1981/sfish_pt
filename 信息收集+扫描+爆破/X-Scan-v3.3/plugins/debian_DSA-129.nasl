# This script was automatically generated from the dsa-129
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14966);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "129");
 script_cve_id("CVE-2002-0912");
 script_bugtraq_id(4910);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-129 security update');
 script_set_attribute(attribute: 'description', value:
'We have received reports that in.uucpd, an authentication agent in the
uucp package, does not properly terminate certain long input strings.
This has been corrected in uucp package version 1.06.1-11potato3 for
Debian 2.2 (potato) and in version 1.06.1-18 for the upcoming (woody)
release.
We recommend you upgrade your uucp package immediately.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-129');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2002/dsa-129
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA129] DSA-129-1 uucp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-129-1 uucp");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'uucp', release: '2.2', reference: '1.06.1-11potato3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
