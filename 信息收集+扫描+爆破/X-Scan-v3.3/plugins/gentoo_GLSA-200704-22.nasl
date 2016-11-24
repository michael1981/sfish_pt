# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200704-22.xml
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
 script_id(25110);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200704-22");
 script_cve_id("CVE-2006-2916", "CVE-2006-4447");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200704-22 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200704-22
(BEAST: Denial of Service)


    BEAST, which is installed as setuid root, fails to properly check
    whether it can drop privileges accordingly if seteuid() fails due to a
    user exceeding assigned resource limits.
  
Impact

    A local user could exceed his resource limit in order to prevent the
    seteuid() call from succeeding. This may lead BEAST to keep running
    with root privileges. Then, the local user could use the "save as"
    dialog box to overwrite any file on the vulnerable system, potentially
    leading to a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All BEAST users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-sound/beast-0.7.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2916');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4447');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200704-22.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200704-22] BEAST: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'BEAST: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-sound/beast", unaffected: make_list("ge 0.7.1"), vulnerable: make_list("lt 0.7.1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
