# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-03.xml
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
 script_id(16440);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200502-03");
 script_cve_id("CVE-2004-1184", "CVE-2004-1185", "CVE-2004-1186");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200502-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200502-03
(enscript: Multiple vulnerabilities)


    Erik Sjolund discovered several issues in enscript: it suffers
    from several buffer overflows (CAN-2004-1186), quotes and shell escape
    characters are insufficiently sanitized in filenames (CAN-2004-1185),
    and it supported taking input from an arbitrary command pipe, with
    unwanted side effects (CAN-2004-1184).
  
Impact

    An attacker could design malicious files or input data which, once
    feeded into enscript, would trigger the execution of arbitrary code
    with the rights of the user running enscript.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All enscript users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/enscript-1.6.3-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1184');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1185');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1186');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200502-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200502-03] enscript: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'enscript: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/enscript", unaffected: make_list("ge 1.6.3-r3"), vulnerable: make_list("lt 1.6.3-r3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
