# This script was automatically generated from the dsa-080
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2008 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2008 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include("compat.inc");

if (description) {
 script_id(14917);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "080");
 script_cve_id("CVE-2001-0834");

 script_set_attribute(attribute: "synopsis", value: "The remote host is missing the DSA-080 security update.");
 script_set_attribute(attribute: "description", value: 
'Nergal reported a vulnerability in the htsearch program which is
distributed as part of the ht://Dig package, an indexing and searching
system for small domains or intranets.  Using former versions it was
able to pass the parameter -c to the cgi program in order to use a
different configuration file.

A malicious user could point htsearch to a file like /dev/zero and
let the server run in an endless loop, trying to read config
parameters.  If the user has write permission on the server they can
point the program to it and retrieve any file readable by the webserver
user id.

This problem has been fixed in version 3.1.5-2.0potato.1 for Debian
GNU/Linux 2.2.');

  script_set_attribute(attribute: "see_also", value: "http://www.debian.org/security/2001/dsa-080");
  script_set_attribute(attribute: "see_also", value: "http://sourceforge.net/tracker/index.php?func=detail&aid=458013&group_id=4593&atid=104593");
 script_set_attribute(attribute:"solution", value:
"Read http://www.debian.org/security/2001/dsa-080 
and install the recommended updated packages." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
script_end_attributes();

 script_copyright(english: "This script is (C) 2008-2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA080] DSA-080-1 htdig");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-080-1 htdig");
 exit(0);
}

include("debian_package.inc");

deb_check(prefix: 'htdig', release: '2.2', reference: '3.1.5-2.0potato.1');
deb_check(prefix: 'htdig-doc', release: '2.2', reference: '3.1.5-2.0potato.1');
if (deb_report_get()) security_warning(port: 0, extra: deb_report_get());
