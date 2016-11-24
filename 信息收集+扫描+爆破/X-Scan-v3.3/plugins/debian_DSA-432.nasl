# This script was automatically generated from the dsa-432
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15269);
 script_version("$Revision: 1.12 $");
 script_xref(name: "DSA", value: "432");
 script_cve_id("CVE-2004-0103");
 script_bugtraq_id(9566);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-432 security update');
 script_set_attribute(attribute: 'description', value:
'Steve Kemp from the Debian Security Audit Project discovered a problem in
crawl, another console based dungeon exploration game, in the vein of
nethack and rogue.  The program uses several environment variables as
inputs but doesn\'t apply a size check before copying one of them into
a fixed size buffer.
For the stable distribution (woody) this problem has been fixed in
version 4.0.0beta23-2woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-432');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your crawl package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA432] DSA-432-1 crawl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-432-1 crawl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'crawl', release: '3.0', reference: '4.0.0beta23-2woody1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
