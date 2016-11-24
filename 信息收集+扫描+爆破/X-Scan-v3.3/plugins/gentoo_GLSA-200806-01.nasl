# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200806-01.xml
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
 script_id(33084);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200806-01");
 script_cve_id("CVE-2008-2357");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200806-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200806-01
(mtr: Stack-based buffer overflow)


    Adam Zabrocki reported a boundary error within the split_redraw()
    function in the file split.c, possibly leading to a stack-based buffer
    overflow.
  
Impact

    A remote attacker could use a specially crafted resolved hostname to
    execute arbitrary code with root privileges. However, it is required
    that the attacker controls the DNS server used by the victim, and that
    the "-p" (or "--split") command line option is used.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All mtr users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/mtr-0.73-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2357');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200806-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200806-01] mtr: Stack-based buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'mtr: Stack-based buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/mtr", unaffected: make_list("ge 0.73-r1"), vulnerable: make_list("lt 0.73-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
