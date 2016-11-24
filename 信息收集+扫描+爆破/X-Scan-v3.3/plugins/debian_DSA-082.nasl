# This script was automatically generated from the dsa-082
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2008 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2008 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include("compat.inc");

if (description) {
 script_id(14919);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "082");
 script_bugtraq_id(2964);

 script_set_attribute(attribute: "synopsis", value: "The remote host is missing the DSA-082 security update.");
 script_set_attribute(attribute: "description", value: 
'Christophe Bailleux reported on bugtraq that Xvt is vulnerable to a
buffer overflow in its argument handling.  Since Xvt is installed
setuid root, it was possible for a normal user to pass
carefully-crafted arguments to xvt so that xvt executed a root shell.

This problem has been fixed by the maintainer in version 2.1-13 of xvt
for Debian unstable and 2.1-13.0potato.1 for the stable Debian
GNU/Linux 2.2.');
   script_set_attribute(attribute: "see_also", value: "http://www.debian.org/security/2001/dsa-082");
  script_set_attribute(attribute:"solution", value:
"Read http://www.debian.org/security/2001/dsa-082 
and install the recommended updated packages." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_end_attributes();

 script_copyright(english: "This script is (C) 2008-2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA082] DSA-082-1 xvt");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_cve_id("CVE-2001-1561");
 script_summary(english: "DSA-082-1 xvt");
 exit(0);
}

include("debian_package.inc");

deb_check(prefix: 'xvt', release: '2.2', reference: '2.1-13.0potato.1');
if (deb_report_get()) security_hole(port: 0, extra: deb_report_get());
