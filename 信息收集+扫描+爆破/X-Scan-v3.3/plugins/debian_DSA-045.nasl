# This script was automatically generated from the dsa-045
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14882);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "045");
 script_cve_id("CVE-2001-0414");
 script_bugtraq_id(2450);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-045 security update');
 script_set_attribute(attribute: 'description', value:
'Przemyslaw Frasunek <venglin@FREEBSD.LUBLIN.PL>
reported that ntp daemons such as that released with Debian GNU/Linux are
vulnerable to a buffer overflow that can lead to a remote root exploit. A
previous advisory (DSA-045-1) partially addressed this issue, but introduced a
potential denial of service attack. This has been corrected for Debian 2.2
(potato) in ntp version 4.0.99g-2potato2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-045');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-045
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA045] DSA-045-2 ntpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-045-2 ntpd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ntp', release: '2.2', reference: '4.0.99g-2potato2');
deb_check(prefix: 'ntp-doc', release: '2.2', reference: '4.0.99g-2potato2');
deb_check(prefix: 'ntpdate', release: '2.2', reference: '4.0.99g-2potato2');
deb_check(prefix: 'xntp3', release: '2.2', reference: '4.0.99g-2potato2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
