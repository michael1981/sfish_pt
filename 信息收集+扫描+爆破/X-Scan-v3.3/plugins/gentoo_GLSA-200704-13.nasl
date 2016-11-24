# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200704-13.xml
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
 script_id(25058);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200704-13");
 script_cve_id("CVE-2007-2026");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200704-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200704-13
(File: Denial of Service)


    Conor Edberg discovered an error in the way file processes a specific
    regular expression.
  
Impact

    A remote attacker could entice a user to open a specially crafted file,
    using excessive CPU ressources and possibly leading to a Denial of
    Service. Note that this vulnerability could be also triggered through
    an automatic file scanner like amavisd-new.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All file users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-apps/file-4.20-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2026');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200704-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200704-13] File: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'File: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-apps/file", unaffected: make_list("ge 4.21-r1"), vulnerable: make_list("eq 4.21")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
