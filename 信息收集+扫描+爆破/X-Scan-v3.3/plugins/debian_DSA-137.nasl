# This script was automatically generated from the dsa-137
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14974);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "137");
 script_cve_id("CVE-2002-0658");
 script_bugtraq_id(5352);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-137 security update');
 script_set_attribute(attribute: 'description', value:
'Marcus Meissner and Sebastian Krahmer discovered and fixed a temporary
file vulnerability in the mm shared memory library.  This problem can
be exploited to gain root access to a machine running Apache which is
linked against this library, if shell access to the user &ldquo;www-data&rdquo;
is already available (which could easily be triggered through PHP).
This problem has been fixed in the upstream version 1.2.0 of mm, which
will be uploaded to the unstable Debian distribution while this
advisory is released.  Fixed packages for potato (Debian 2.2) and
woody (Debian 3.0) are linked below.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-137');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libmm packages immediately and
restart your Apache server.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA137] DSA-137-1 mm");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-137-1 mm");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmm10', release: '2.2', reference: '1.0.11-1.2');
deb_check(prefix: 'libmm10-dev', release: '2.2', reference: '1.0.11-1.2');
deb_check(prefix: 'libmm11', release: '3.0', reference: '1.1.3-6.1');
deb_check(prefix: 'libmm11-dev', release: '3.0', reference: '1.1.3-6.1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
