# This script was automatically generated from the dsa-809
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19684);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "809");
 script_cve_id("CVE-2005-2794", "CVE-2005-2796");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-809 security update');
 script_set_attribute(attribute: 'description', value:
'Certain aborted requests that trigger an assertion in squid, the
popular WWW proxy cache, may allow remote attackers to cause a denial
of service.  This update also fixes a regression caused by
DSA 751.
For completeness below is the original advisory text:
Several vulnerabilities have been discovered in Squid, the popular WWW
proxy cache.  The Common Vulnerabilities and Exposures project
identifies the following problems:
    Certain aborted requests that trigger an assert may allow remote
    attackers to cause a denial of service.
    Specially crafted requests can cause a denial of service.
For the oldstable distribution (woody) this problem has been fixed in
version 2.4.6-2woody10.
For the stable distribution (sarge) these problems have been fixed in
version 2.5.9-10sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-809');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your squid package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA809] DSA-809-2 squid");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-809-2 squid");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'squid', release: '3.0', reference: '2.4.6-2woody10');
deb_check(prefix: 'squid-cgi', release: '3.0', reference: '2.4.6-2woody10');
deb_check(prefix: 'squidclient', release: '3.0', reference: '2.4.6-2woody10');
deb_check(prefix: 'squid', release: '3.1', reference: '2.5.9-10sarge1');
deb_check(prefix: 'squid-cgi', release: '3.1', reference: '2.5.9-10sarge1');
deb_check(prefix: 'squid-common', release: '3.1', reference: '2.5.9-10sarge1');
deb_check(prefix: 'squidclient', release: '3.1', reference: '2.5.9-10sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
