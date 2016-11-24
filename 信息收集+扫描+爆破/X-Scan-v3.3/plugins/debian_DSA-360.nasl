# This script was automatically generated from the dsa-360
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15197);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "360");
 script_cve_id("CVE-2003-0581", "CVE-2003-0625");
 script_bugtraq_id(8182, 8255);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-360 security update');
 script_set_attribute(attribute: 'description', value:
'xfstt, a TrueType font server for the X window system was found to
contain two classes of vulnerabilities:
  CVE-2003-0581: a remote attacker could send requests crafted to
  trigger any of several buffer overruns, causing a denial of service or
  possibly executing arbitrary code on the server with the privileges
  of the "nobody" user.
  CVE-2003-0625: certain invalid data sent during the connection
  handshake could allow a remote attacker to read certain regions of
  memory belonging to the xfstt process.  This information could be
  used for fingerprinting, or to aid in exploitation of a different
  vulnerability.
For the current stable distribution (woody) these problems have been
fixed in version 1.2.1-3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-360');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-360
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA360] DSA-360-1 xfstt");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-360-1 xfstt");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xfstt', release: '3.0', reference: '1.2.1-3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
