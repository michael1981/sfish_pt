# This script was automatically generated from the dsa-066
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14903);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "066");
 script_cve_id("CVE-2001-0735");
 script_bugtraq_id(2914, 2915);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-066 security update');
 script_set_attribute(attribute: 'description', value:
'Steven van Acker reported on bugtraq that the version of cfingerd (a
configurable finger daemon) as distributed in Debian GNU/Linux 2.2
suffers from two problems:


The code that reads configuration files (files in which $ commands are
   expanded) copied its input to a buffer without checking for a buffer
   overflow. When the ALLOW_LINE_PARSING feature is enabled that code
   is used for reading users\' files as well, so local users could exploit
   this.

There also was a printf call in the same routine that did not protect
   against printf format attacks.


Since ALLOW_LINE_PARSING is enabled in the default /etc/cfingerd.conf
local users could use this to gain root access.

This has been fixed in version 1.4.1-1.2, and we recommend that you upgrade
your cfingerd package immediately.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-066');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-066
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA066] DSA-066-1 cfingerd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-066-1 cfingerd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cfingerd', release: '2.2', reference: '1.4.1-1.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
