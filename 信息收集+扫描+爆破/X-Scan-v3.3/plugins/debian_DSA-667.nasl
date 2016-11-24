# This script was automatically generated from the dsa-667
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16341);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "667");
 script_cve_id("CVE-2005-0173", "CVE-2005-0175", "CVE-2005-0194", "CVE-2005-0211");
 script_xref(name: "CERT", value: "625878");
 script_xref(name: "CERT", value: "886006");
 script_xref(name: "CERT", value: "924198");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-667 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in Squid, the internet
object cache, the popular WWW proxy cache.  The Common Vulnerabilities
and Exposures project identifies the following vulnerabilities:
    LDAP is very forgiving about spaces in search filters and this
    could be abused to log in using several variants of the login
    name, possibly bypassing explicit access controls or confusing
    accounting.
    Cache pollution/poisoning via HTTP response splitting has been
    discovered.
    The meaning of the access controls becomes somewhat confusing if
    any of the referenced ACLs (access control lists) is declared
    empty, without any members.
    The length argument of the WCCP recvfrom() call is larger than it
    should be.  An attacker may send a larger than normal WCCP packet
    that could overflow a buffer.
For the stable distribution (woody) these problems have been fixed in
version 2.4.6-2woody6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-667');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your squid package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA667] DSA-667-1 squid");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-667-1 squid");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'squid', release: '3.0', reference: '2.4.6-2woody6');
deb_check(prefix: 'squid-cgi', release: '3.0', reference: '2.4.6-2woody6');
deb_check(prefix: 'squidclient', release: '3.0', reference: '2.4.6-2woody6');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
