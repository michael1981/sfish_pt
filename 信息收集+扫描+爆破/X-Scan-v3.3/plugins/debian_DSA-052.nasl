# This script was automatically generated from the dsa-052
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2008 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2008 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include("compat.inc");

if (description)
{
 script_id(14889);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "052");
 script_cve_id("CVE-2001-0623");

 script_set_attribute(attribute: "synopsis", value: "The remote host is missing the DSA-052 security update.");
 script_set_attribute(attribute: "description", value: 
'Daniel Kobras has discovered and fixed a problem in sendfiled which
caused the daemon not to drop privileges as expected when sending
notification mails. Exploiting this, a local user can easily make it
execute arbitrary code under root privileges.');
 script_set_attribute(attribute: "see_also", value: "http://www.debian.org/security/2001/dsa-052");
 script_set_attribute(attribute:"solution", value:
"Read http://www.debian.org/security/2001/dsa-052 
and install the recommended updated packages." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_end_attributes();

 script_copyright(english: "This script is (C) 2008-2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA052] DSA-052-1 sendfile");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-052-1 sendfile");
 exit(0);
}

include("debian_package.inc");

deb_check(prefix: 'sendfile', release: '2.2', reference: '2.1-20.3');
if (deb_report_get()) security_warning(port: 0, extra: deb_report_get());
