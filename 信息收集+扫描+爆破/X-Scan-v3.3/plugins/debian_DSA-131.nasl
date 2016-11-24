# This script was automatically generated from the dsa-131
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14968);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "131");
 script_cve_id("CVE-2002-0392");
 script_bugtraq_id(5033);
 script_xref(name: "CERT", value: "944335");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-131 security update');
 script_set_attribute(attribute: 'description', value:
'Mark Litchfield found a denial of service attack in the Apache
web-server. While investigating the problem the Apache Software
Foundation discovered that the code for handling invalid requests which
use chunked encoding also might allow arbitrary code execution on 64
bit architectures.
This has been fixed in version 1.3.9-14.1 of the Debian apache package,
as well as upstream versions 1.3.26 and 2.0.37. We strongly recommend
that you upgrade your apache package immediately.
The package upgrade does not restart the apache server automatically,
this will have to be done manually. Please make sure your
configuration is correct ("apachectl configtest" will verify that for
you) and restart it using "/etc/init.d/apache restart"
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-131');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2002/dsa-131
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA131] DSA-131-1 apache");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-131-1 apache");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'apache', release: '2.2', reference: '1.3.9-14.1');
deb_check(prefix: 'apache-common', release: '2.2', reference: '1.3.9-14.1');
deb_check(prefix: 'apache-dev', release: '2.2', reference: '1.3.9-14.1');
deb_check(prefix: 'apache-doc', release: '2.2', reference: '1.3.9-14.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
