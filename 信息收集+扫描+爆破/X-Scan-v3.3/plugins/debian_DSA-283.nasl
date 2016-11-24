# This script was automatically generated from the dsa-283
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15120);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "283");
 script_cve_id("CVE-2003-0173");
 script_bugtraq_id(7321);
 script_xref(name: "CERT", value: "111673");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-283 security update');
 script_set_attribute(attribute: 'description', value:
'Ethan Benson discovered a problem in xfsdump, that contains
administrative utilities for the XFS filesystem.  When filesystem
quotas are enabled xfsdump runs xfsdq to save the quota information
into a file at the root of the filesystem being dumped.  The manner in
which this file is created is unsafe.
While fixing this, a new option &ldquo;-f path&rdquo; has been added to xfsdq(8)
to specify an output file instead of using the standard output stream.
This file is created by xfsdq and xfsdq will fail to run if it exists
already.  The file is also created with a more appropriate mode than
whatever the umask happened to be when xfsdump(8) was run.
For the stable distribution (woody) this problem has been fixed in
version 2.0.1-2.
The old stable distribution (potato) is not affected since it doesn\'t
contain xfsdump packages.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-283');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xfsdump package immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA283] DSA-283-1 xfsdump");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-283-1 xfsdump");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xfsdump', release: '3.0', reference: '2.0.1-2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
