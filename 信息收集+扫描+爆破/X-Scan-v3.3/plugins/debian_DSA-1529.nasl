# This script was automatically generated from the dsa-1529
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38955);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "1529");
 script_cve_id("CVE-2006-7211", "CVE-2006-7212", "CVE-2006-7213", "CVE-2006-7214", "CVE-2007-2606", "CVE-2007-3181", "CVE-2007-3527");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1529 security update');
 script_set_attribute(attribute: 'description', value:
'Multiple security problems have been discovered in the Firebird database,
which may lead to the execution of arbitrary code or denial of service.


This Debian security advisory is a bit unusual. While it\'s normally 
our strict policy to backport security bugfixes to older releases, this
turned out to be infeasible for Firebird 1.5 due to large infrastructural
changes necessary to fix these issues. As a consequence security support
for Firebird 1.5 is hereby discontinued, leaving two options to
administrators running a Firebird database:

For a more detailed description of the security problems, please refer
to the entries in the Debian Bug Tracking System referenced above and
the following URLs:

http://www.firebirdsql.org/rlsnotes/Firebird-2.0-ReleaseNotes.pdf/
http://www.firebirdsql.org/rlsnotes/Firebird-2.0.1-ReleaseNotes.pdf/
http://www.firebirdsql.org/rlsnotes/Firebird-2.0.2-ReleaseNotes.pdf
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1529');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2008/dsa-1529
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1529] DSA-1529-1 firebird");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1529-1 firebird");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
