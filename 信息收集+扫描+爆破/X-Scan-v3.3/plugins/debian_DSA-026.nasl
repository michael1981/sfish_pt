# This script was automatically generated from the dsa-026
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14863);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "026");
 script_cve_id("CVE-2001-0010", "CVE-2001-0012");
 script_xref(name: "CERT", value: "196945");
 script_xref(name: "CERT", value: "325431");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-026 security update');
 script_set_attribute(attribute: 'description', value:
'BIND 8 suffered from several buffer overflows. It is
possible to construct an inverse query that allows the stack to be read
remotely exposing environment variables. CERT has disclosed information about
these issues. A new upstream version fixes this. Due to the complexity of BIND
we have decided to make an exception to our rule by releasing the new upstream
source to our stable distribution. We recommend you upgrade your bind packages
immediately.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-026');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-026
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA026] DSA-026-1 bind");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-026-1 bind");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'bind', release: '2.2', reference: '8.2.3-0.potato.1');
deb_check(prefix: 'bind-dev', release: '2.2', reference: '8.2.3-0.potato.1');
deb_check(prefix: 'dnsutils', release: '2.2', reference: '8.2.3-0.potato.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
