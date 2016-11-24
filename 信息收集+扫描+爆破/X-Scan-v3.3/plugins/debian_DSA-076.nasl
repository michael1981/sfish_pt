# This script was automatically generated from the dsa-076
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2008 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2008 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include("compat.inc");

if (description)
{
 script_id(14913);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "076");
 script_cve_id("CVE-2001-0961");
 script_bugtraq_id(3347);

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing the DSA-076 security update." );
 script_set_attribute(attribute:"description", value: '
Pavel Machek has found a buffer overflow in the `most\' pager program.
The problem is part of most\'s tab expansion where the program would
write beyond the bounds two array variables when viewing a malicious
file.  This could lead into other data structures being overwritten
which in turn could enable most to execute arbitrary code being able
to compromise the users environment.

This has been fixed in the upstream version 4.9.2 and an updated
version of 4.9.0 for Debian GNU/Linux 2.2.');
 script_set_attribute(attribute:"see_also", value:"http://www.debian.org/security/2001/dsa-076");
 script_set_attribute(attribute:"solution", value:
"Read http://www.debian.org/security/2001/dsa-076 
and install the recommended updated packages." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_end_attributes();

 script_copyright(english: "This script is (C) 2008-2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA076] DSA-076-1 most");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-076-1 most");
 exit(0);
}

include("debian_package.inc");

deb_check(prefix: 'most', release: '2.2', reference: '4.9.0-2.1');
if (deb_report_get()) security_hole(port: 0, extra: deb_report_get());
