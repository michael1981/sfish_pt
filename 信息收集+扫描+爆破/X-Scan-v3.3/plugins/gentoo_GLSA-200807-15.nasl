# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200807-15.xml
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
 script_id(33781);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200807-15");
 script_cve_id("CVE-2008-2363");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200807-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200807-15
(Pan: User-assisted execution of arbitrary code)


    Pavel Polischouk reported a boundary error in the PartsBatch class when
    processing .nzb files.
  
Impact

    A remote attacker could entice a user to open a specially crafted .nzb
    file, possibly resulting in the remote execution of arbitrary code with
    the privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Pan users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-nntp/pan-0.132-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2363');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200807-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200807-15] Pan: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Pan: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-nntp/pan", unaffected: make_list("ge 0.132-r3", "rge 0.14.2.91-r2", "eq 0.14.2"), vulnerable: make_list("lt 0.132-r3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
