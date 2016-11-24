# This script was automatically generated from the dsa-053
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14890);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "053");
 script_cve_id("CVE-2001-0556");
 script_bugtraq_id(2667);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-053 security update');
 script_set_attribute(attribute: 'description', value:
'The nedit (Nirvana editor) package as shipped in the non-free section
accompanying Debian GNU/Linux 2.2/potato had a bug in its printing code:
when printing text it would create a temporary file with the to be
printed text and pass that on to the print system. The temporary file
was not created safely, which could be exploited by an attacked to make
nedit overwrite arbitrary files.

This has been fixed in version 5.02-7.1.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-053');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-053
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA053] DSA-053-1 nedit");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-053-1 nedit");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'nedit', release: '2.2', reference: '5.02-7.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
