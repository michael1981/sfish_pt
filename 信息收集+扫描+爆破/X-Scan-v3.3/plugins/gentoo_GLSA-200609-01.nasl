# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200609-01.xml
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
 script_id(22323);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200609-01");
 script_cve_id("CVE-2006-3124");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200609-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200609-01
(Streamripper: Multiple remote buffer overflows)


    Ulf Harnhammar, from the Debian Security Audit Project, has found that
    Streamripper is vulnerable to multiple stack based buffer overflows
    caused by improper bounds checking when processing malformed HTTP
    headers.
  
Impact

    By enticing a user to connect to a malicious server, an attacker could
    execute arbitrary code with the permissions of the user running
    Streamripper
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Streamripper users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-sound/streamripper-1.61.26"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3124');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200609-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200609-01] Streamripper: Multiple remote buffer overflows');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Streamripper: Multiple remote buffer overflows');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-sound/streamripper", unaffected: make_list("ge 1.61.26"), vulnerable: make_list("lt 1.61.26")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
