# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-29.xml
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
 script_id(14797);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200409-29");
 script_cve_id("CVE-2004-0938", "CVE-2004-0960", "CVE-2004-0961");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200409-29 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200409-29
(FreeRADIUS: Multiple Denial of Service vulnerabilities)


    There are undisclosed defects in the way FreeRADIUS handles incorrect
    received packets.
  
Impact

    A remote attacker could send specially-crafted packets to the
    FreeRADIUS server to deny service to other users by crashing the
    server.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All FreeRADIUS users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-dialup/freeradius-1.0.1"
    # emerge ">=net-dialup/freeradius-1.0.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.freeradius.org/security.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0938');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0960');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0961');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200409-29.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200409-29] FreeRADIUS: Multiple Denial of Service vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'FreeRADIUS: Multiple Denial of Service vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-dialup/freeradius", unaffected: make_list("ge 1.0.1"), vulnerable: make_list("lt 1.0.1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
