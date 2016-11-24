# This script was automatically generated from the dsa-117
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14954);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "117");
 script_cve_id("CVE-2002-0092");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-117 security update');
 script_set_attribute(attribute: 'description', value:
'Kim Nielsen recently found an internal problem with the CVS server and
reported it to the vuln-dev mailing list.  The problem is triggered by
an improperly initialized global variable.  A user exploiting this can
crash the CVS server, which may be accessed through the pserver
service and running under a remote user id.  It is not yet clear if
the remote account can be exposed, though.
This problem has been fixed in version 1.10.7-9 for the stable Debian
distribution with help of Niels Heinen and in versions newer
than 1.11.1p1debian-3 for the
testing and unstable distribution of Debian (not yet uploaded,
though).
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-117');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your CVS package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA117] DSA-117-1 cvs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-117-1 cvs");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cvs', release: '2.2', reference: '1.10.7-9');
deb_check(prefix: 'cvs-doc', release: '2.2', reference: '1.10.7-9');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
