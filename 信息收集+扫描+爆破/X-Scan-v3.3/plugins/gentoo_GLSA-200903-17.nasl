# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200903-17.xml
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
 script_id(35815);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200903-17");
 script_cve_id("CVE-2008-4770");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200903-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200903-17
(Real VNC: User-assisted execution of arbitrary code)


    An unspecified vulnerability has been discovered int the
    CMsgReader::readRect() function in the VNC Viewer component, related to
    the encoding type of RFB protocol data.
  
Impact

    A remote attacker could entice a user to connect to a malicious VNC
    server, or leverage Man-in-the-Middle attacks, to cause the execution
    of arbitrary code with the privileges of the user running the VNC
    viewer.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Real VNC users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/vnc-4.1.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4770');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200903-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200903-17] Real VNC: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Real VNC: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/vnc", unaffected: make_list("ge 4.1.3"), vulnerable: make_list("lt 4.1.3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
