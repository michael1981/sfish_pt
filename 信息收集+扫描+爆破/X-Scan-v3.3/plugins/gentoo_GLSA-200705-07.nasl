# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200705-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(25184);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200705-07");
 script_cve_id("CVE-2007-1869", "CVE-2007-1870");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200705-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200705-07
(Lighttpd: Two Denials of Service)


    Robert Jakabosky discovered an infinite loop triggered by a connection
    abort when Lighttpd processes carriage return and line feed sequences.
    Marcus Rueckert discovered a NULL pointer dereference when a server
    running Lighttpd tries to access a file with a mtime of 0.
  
Impact

    A remote attacker could upload a specially crafted file to the server
    or send a specially crafted request and then abort the connection,
    possibly resulting in a crash or a Denial of Service by CPU
    consumption.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Lighttpd users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-servers/lighttpd-1.4.14"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1869');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1870');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200705-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200705-07] Lighttpd: Two Denials of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Lighttpd: Two Denials of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/lighttpd", unaffected: make_list("ge 1.4.14"), vulnerable: make_list("lt 1.4.14")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
