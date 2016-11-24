# This script was automatically generated from the dsa-144
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14981);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "144");
 script_cve_id("CVE-2002-0818");
 script_bugtraq_id(5260);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-144 security update');
 script_set_attribute(attribute: 'description', value:
'A problem with wwwoffle has been discovered.  The web proxy didn\'t
handle input data with negative Content-Length settings properly which
causes the processing child to crash.  It is at this time not obvious
how this can lead to an exploitable vulnerability; however, it\'s better
to be safe than sorry, so here\'s an update.
Additionally, in the woody version empty passwords will be treated as
wrong when trying to authenticate.  In the woody version we also
replaced CanonicaliseHost() with the latest routine from 2.7d, offered
by upstream.  This stops bad IPv6 format IP addresses in URLs from
causing problems (memory overwriting, potential exploits).
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-144');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your wwwoffle packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA144] DSA-144-1 wwwoffle");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-144-1 wwwoffle");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'wwwoffle', release: '2.2', reference: '2.5c-10.4');
deb_check(prefix: 'wwwoffle', release: '3.0', reference: '2.7a-1.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
