# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200802-03.xml
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
 script_id(31033);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200802-03");
 script_cve_id("CVE-2007-6018");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200802-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200802-03
(Horde IMP: Security bypass)


    Ulf Harnhammar, Secunia Research discovered that the "frame" and
    "frameset" HTML tags are not properly filtered out. He also reported
    that certain HTTP requests are executed without being checked.
  
Impact

    A remote attacker could entice a user to open a specially crafted HTML
    e-mail, possibly resulting in the deletion of arbitrary e-mail
    messages.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Horde IMP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/horde-imp-4.1.6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6018');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200802-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200802-03] Horde IMP: Security bypass');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Horde IMP: Security bypass');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/horde-imp", unaffected: make_list("ge 4.1.6"), vulnerable: make_list("lt 4.1.6")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
