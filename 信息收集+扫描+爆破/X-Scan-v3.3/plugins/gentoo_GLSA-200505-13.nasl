# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-13.xml
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
 script_id(18272);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200505-13");
 script_cve_id("CVE-2005-1454", "CVE-2005-1455");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200505-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200505-13
(FreeRADIUS: SQL injection and Denial of Service vulnerability)


    Primoz Bratanic discovered that the sql_escape_func function of
    FreeRADIUS may be vulnerable to a buffer overflow (BID 13541). He also
    discovered that FreeRADIUS fails to sanitize user-input before using it
    in a SQL query, possibly allowing SQL command injection (BID 13540).
  
Impact

    By supplying carefully crafted input, a malicious user could cause an
    SQL injection or a buffer overflow, possibly leading to the disclosure
    and the modification of sensitive data or Denial of Service by crashing
    the server.
  
Workaround

    There are no known workarounds at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All FreeRADIUS users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-dialup/freeradius-1.0.2-r4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.securityfocus.com/bid/13540/');
script_set_attribute(attribute: 'see_also', value: 'http://www.securityfocus.com/bid/13541/');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1454');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1455');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200505-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200505-13] FreeRADIUS: SQL injection and Denial of Service vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'FreeRADIUS: SQL injection and Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-dialup/freeradius", unaffected: make_list("ge 1.0.2-r4"), vulnerable: make_list("lt 1.0.2-r4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
