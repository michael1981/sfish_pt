# This script was automatically generated from the dsa-396
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15233);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "396");
 script_cve_id("CVE-2002-1562", "CVE-2003-0899");
 script_bugtraq_id(8906, 8924);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-396 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in thttpd, a tiny HTTP
server.
The Common Vulnerabilities and Exposures project identifies the
following vulnerabilities:
  Marcus Breiing discovered that if thttpd it is used for virtual
  hosting, and an attacker supplies a specially crafted &ldquo;Host:&rdquo;
  header with a pathname instead of a hostname, thttpd will reveal
  information about the host system.  Hence, an attacker can browse
  the entire disk.
  Joel Söderberg and Christer Öberg discovered a remote overflow which
  allows an attacker to partially overwrite the EBP register and
  hence execute arbitrary code.
For the stable distribution (woody) these problems have been fixed in
version 2.21b-11.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-396');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your thttpd package immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA396] DSA-396-1 thttpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-396-1 thttpd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'thttpd', release: '3.0', reference: '2.21b-11.2');
deb_check(prefix: 'thttpd-util', release: '3.0', reference: '2.21b-11.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
